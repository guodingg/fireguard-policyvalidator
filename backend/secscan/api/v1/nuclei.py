"""
Nuclei API - 增强版，包含离线更新
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File
from pydantic import BaseModel
from typing import List, Optional
import zipfile
import io
import shutil
from pathlib import Path

from secscan.models.user import User
from secscan.api.v1.auth import get_current_user
from secscan.services.nuclei_service import NucleiService

router = APIRouter(prefix="/nuclei", tags=["Nuclei漏洞库"])

class TemplateUpdateResponse(BaseModel):
    success: bool
    message: str
    templates_count: int
    templates_dir: str

@router.get("/templates")
async def get_templates():
    """获取模板库概览"""
    templates = NucleiService.get_templates()
    return templates

@router.post("/templates/update")
async def update_templates(background_tasks: BackgroundTasks):
    """在线更新Nuclei模板库"""
    result = await NucleiService.update_templates()
    return result

@router.post("/templates/update/offline")
async def update_templates_offline(
    file: UploadFile = File(...)
):
    """
    离线更新Nuclei模板库
    上传包含nuclei-templates的ZIP压缩包
    """
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="只支持ZIP格式")
    
    content = await file.read()
    
    try:
        zip_buffer = io.BytesIO(content)
        template_dir = Path(NucleiService.get_template_dir())
        
        # 验证ZIP内容
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            file_list = zf.namelist()
            
            # 检查是否包含nuclei-templates
            has_templates = any('nuclei-templates' in f or f.endswith('.yaml') or f.endswith('.yml') for f in file_list)
            
            if not has_templates:
                raise HTTPException(status_code=400, detail="ZIP包中未找到Nuclei模板")
        
        # 备份现有模板（如果有）
        backup_dir = template_dir.parent / "nuclei-templates-backup"
        if template_dir.exists():
            if backup_dir.exists():
                shutil.rmtree(backup_dir)
            shutil.copytree(template_dir, backup_dir)
        
        # 解压新模板
        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            # 提取到临时目录
            temp_dir = template_dir.parent / "nuclei-templates-temp"
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            
            for member in zf.namelist():
                # 跳过顶层目录名称差异
                if member.startswith('nuclei-templates/'):
                    # 去除前缀
                    target_name = member[len('nuclei-templates/'):]
                    if target_name:
                        zf.extract(member, temp_dir)
                elif not member.endswith('/'):  # 根目录文件
                    zf.extract(member, temp_dir)
        
        # 移动到正确位置
        if temp_dir.exists():
            # 查找实际的模板目录
            actual_template_dir = None
            for item in temp_dir.iterdir():
                if item.is_dir() and (item / 'nuclei-templates' ).exists():
                    actual_template_dir = item / 'nuclei-templates'
                    break
                elif list(item.glob('*.yaml')):
                    actual_template_dir = item
                    break
            
            if actual_template_dir:
                if template_dir.exists():
                    shutil.rmtree(template_dir)
                shutil.move(str(actual_template_dir), str(template_dir))
                shutil.rmtree(temp_dir)
        
        # 统计新模板
        templates = list(template_dir.rglob("*.yaml")) if template_dir.exists() else []
        
        # 清理备份
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        
        return {
            "success": True,
            "message": "离线更新成功",
            "templates_count": len(templates),
            "templates_dir": str(template_dir)
        }
        
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="无效的ZIP文件")
    except Exception as e:
        # 恢复备份
        backup_dir = template_dir.parent / "nuclei-templates-backup"
        if backup_dir.exists():
            if template_dir.exists():
                shutil.rmtree(template_dir)
            shutil.move(str(backup_dir), str(template_dir))
        
        raise HTTPException(status_code=500, detail=f"离线更新失败: {str(e)}")

@router.get("/templates/search")
async def search_templates(
    keyword: str = None,
    severity: str = None,
    category: str = None,
    tags: str = None,
    limit: int = 100
):
    """搜索模板"""
    tag_list = tags.split(",") if tags else None
    
    results = await NucleiService.search_templates(
        keyword=keyword,
        severity=severity,
        category=category,
        tags=tag_list,
        limit=limit
    )
    
    return {"results": results, "count": len(results)}

@router.get("/templates/{template_id}")
async def get_template_detail(template_id: str):
    """获取模板详情"""
    template = NucleiService.get_template_detail(template_id)
    
    if not template:
        raise HTTPException(status_code=404, detail="模板不存在")
    
    return template

@router.get("/categories")
async def get_categories():
    """获取所有分类"""
    templates = NucleiService.get_templates()
    categories = templates.get("templates_by_category", {})
    return {"categories": categories}

@router.get("/stats")
async def get_nuclei_stats():
    """获取Nuclei统计信息"""
    import shutil
    
    template_dir = Path(NucleiService.get_template_dir())
    
    stats = {
        "installed": template_dir.exists(),
        "templates_dir": str(template_dir),
        "templates_count": 0,
        "disk_usage": 0,
        "categories": {}
    }
    
    if template_dir.exists():
        templates = list(template_dir.rglob("*.yaml"))
        stats["templates_count"] = len(templates)
        
        # 计算磁盘使用
        total_size = sum(f.stat().st_size for f in template_dir.rglob('*') if f.is_file())
        stats["disk_usage"] = total_size
        
        # 分类统计
        categories = {}
        for t in templates[:500]:
            try:
                import yaml
                with open(t, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'info' in data:
                        cat = data['info'].get('category', 'other')
                        categories[cat] = categories.get(cat, 0) + 1
            except:
                pass
        
        stats["categories"] = categories
    
    return stats
