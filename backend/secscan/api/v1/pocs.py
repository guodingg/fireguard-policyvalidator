"""
POC管理API - 增强版，包含自定义导入
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
import yaml
import json
import zipfile
import io
from pathlib import Path

from secscan.database import get_db
from secscan.models.user import User
from secscan.models.vuln import POC
from secscan.api.v1.auth import get_current_user

router = APIRouter(prefix="/pocs", tags=["POC管理"])

@router.get("/")
async def list_pocs(
    skip: int = 0,
    limit: int = 100,
    source: str = None,
    severity: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """POC列表"""
    query = select(POC).order_by(POC.use_count.desc())
    
    if source:
        query = query.where(POC.source == source)
    if severity:
        query = query.where(POC.severity == severity)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    pocs = result.scalars().all()
    
    return [
        {
            "id": p.id,
            "name": p.name,
            "name_cn": p.name_cn,
            "source": p.source,
            "severity": p.severity.value if p.severity else None,
            "cve": p.cve,
            "category": p.category,
            "protocol": p.protocol,
            "tags": p.tags or [],
            "ai_generated": p.ai_generated,
            "use_count": p.use_count,
            "created_at": p.created_at.isoformat() if p.created_at else None
        }
        for p in pocs
    ]

@router.get("/{poc_id}")
async def get_poc(
    poc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取POC详情"""
    result = await db.execute(select(POC).where(POC.id == poc_id))
    poc = result.scalar_one_or_none()
    
    if not poc:
        raise HTTPException(status_code=404, detail="POC不存在")
    
    return {
        "id": poc.id,
        "name": poc.name,
        "name_cn": poc.name_cn,
        "source": poc.source,
        "severity": poc.severity.value if poc.severity else None,
        "cve": poc.cve,
        "cwe": poc.cwe,
        "category": poc.category,
        "protocol": poc.protocol,
        "tags": poc.tags or [],
        "template": poc.template,
        "ai_generated": poc.ai_generated,
        "use_count": poc.use_count,
        "success_count": poc.success_count,
        "created_at": poc.created_at.isoformat() if poc.created_at else None
    }

@router.post("/import/yaml")
async def import_poc_yaml(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """导入单个YAML格式POC"""
    if not file.filename.endswith(('.yaml', '.yml')):
        raise HTTPException(status_code=400, detail="只支持YAML格式")
    
    content = await file.read()
    
    try:
        poc_data = yaml.safe_load(content)
        
        if not poc_data:
            raise HTTPException(status_code=400, detail="POC内容为空")
        
        # 解析POC
        info = poc_data.get('info', {})
        
        poc = POC(
            name=info.get('name', file.filename),
            name_cn=info.get('name', ''),
            source='custom',
            source_id=info.get('file', ''),
            severity=info.get('severity', 'medium'),
            cve=info.get('cve-id', ''),
            cwe=info.get('cwe-id', ''),
            category=info.get('classification', {}).get('category', ''),
            tags=info.get('tags', []),
            protocol=poc_data.get('network', ''),
            template=content.decode('utf-8') if isinstance(content, bytes) else content,
            ai_generated=False
        )
        
        db.add(poc)
        await db.commit()
        await db.refresh(poc)
        
        return {
            "id": poc.id,
            "name": poc.name,
            "message": "POC导入成功"
        }
        
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"YAML解析失败: {str(e)}")

@router.post("/import/zip")
async def import_poc_zip(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """批量导入ZIP压缩包（包含多个POC）"""
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="只支持ZIP格式")
    
    content = await file.read()
    
    try:
        zip_buffer = io.BytesIO(content)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            # 获取所有yaml/yml文件
            yaml_files = [f for f in zf.namelist() if f.endswith(('.yaml', '.yml'))]
            
            if not yaml_files:
                raise HTTPException(status_code=400, detail="ZIP包中未找到YAML文件")
            
            imported = 0
            failed = 0
            errors = []
            
            for yaml_file in yaml_files:
                try:
                    file_content = zf.read(yaml_file)
                    poc_data = yaml.safe_load(file_content)
                    
                    if not poc_data:
                        failed += 1
                        errors.append(f"{yaml_file}: 空文件")
                        continue
                    
                    info = poc_data.get('info', {})
                    
                    poc = POC(
                        name=info.get('name', yaml_file),
                        name_cn=info.get('name', ''),
                        source='custom',
                        source_id=yaml_file,
                        severity=info.get('severity', 'medium'),
                        cve=info.get('cve-id', ''),
                        cwe=info.get('cwe-id', ''),
                        category=info.get('classification', {}).get('category', ''),
                        tags=info.get('tags', []),
                        protocol=poc_data.get('network', ''),
                        template=file_content.decode('utf-8'),
                        ai_generated=False
                    )
                    
                    db.add(poc)
                    imported += 1
                    
                except Exception as e:
                    failed += 1
                    errors.append(f"{yaml_file}: {str(e)}")
            
            await db.commit()
            
            return {
                "imported": imported,
                "failed": failed,
                "errors": errors[:10] if errors else [],  # 最多返回10个错误
                "message": f"导入完成: {imported}成功, {failed}失败"
            }
            
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="无效的ZIP文件")

@router.post("/import/nuclei")
async def import_from_nuclei(
    template_path: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """从本地Nuclei模板导入"""
    path = Path(template_path)
    
    if not path.exists():
        raise HTTPException(status_code=404, detail="模板文件不存在")
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            raise HTTPException(status_code=400, detail="模板内容为空")
        
        info = data.get('info', {})
        
        poc = POC(
            name=info.get('name', path.stem),
            name_cn=info.get('name', ''),
            source='nuclei',
            source_id=data.get('id', path.stem),
            severity=info.get('severity', 'medium'),
            cve=info.get('cve-id', ''),
            cwe=info.get('cwe-id', ''),
            category=info.get('category', ''),
            tags=info.get('tags', []),
            protocol=data.get('network', ''),
            template=open(path, 'r', encoding='utf-8').read(),
            ai_generated=False
        )
        
        db.add(poc)
        await db.commit()
        await db.refresh(poc)
        
        return {
            "id": poc.id,
            "name": poc.name,
            "message": "从Nuclei模板导入成功"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"导入失败: {str(e)}")

@router.delete("/{poc_id}")
async def delete_poc(
    poc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """删除POC"""
    # 只有管理员或POC创建者可删除
    result = await db.execute(select(POC).where(POC.id == poc_id))
    poc = result.scalar_one_or_none()
    
    if not poc:
        raise HTTPException(status_code=404, detail="POC不存在")
    
    if poc.source not in ['custom', 'ai']:
        raise HTTPException(status_code=400, detail="内置POC不可删除")
    
    await db.delete(poc)
    await db.commit()
    
    return {"message": "POC已删除"}

@router.post("/test/{poc_id}")
async def test_poc(
    poc_id: int,
    target: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """测试POC"""
    result = await db.execute(select(POC).where(POC.id == poc_id))
    poc = result.scalar_one_or_none()
    
    if not poc:
        raise HTTPException(status_code=404, detail="POC不存在")
    
    # 更新使用次数
    poc.use_count += 1
    
    # TODO: 实际执行POC测试
    # 这里可以调用Nuclei或自定义执行器
    
    await db.commit()
    
    return {
        "message": "POC测试功能开发中",
        "poc_id": poc_id,
        "target": target
    }

@router.get("/templates/nuclei")
async def list_nuclei_templates(
    category: str = None,
    severity: str = None,
    current_user: User = Depends(get_current_user)
):
    """列出本地Nuclei模板"""
    from secscan.services.nuclei_service import NucleiService
    
    templates_dir = NucleiService.get_template_dir()
    path = Path(templates_dir)
    
    if not path.exists():
        return {"templates": [], "count": 0}
    
    templates = []
    for yaml_file in path.rglob("*.yaml"):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data or 'info' not in data:
                continue
            
            info = data['info']
            
            # 过滤
            if category and info.get('category', '') != category:
                continue
            if severity and info.get('severity', '') != severity:
                continue
            
            templates.append({
                "id": data.get('id', yaml_file.stem),
                "name": info.get('name', ''),
                "severity": info.get('severity', ''),
                "category": info.get('category', ''),
                "tags": info.get('tags', []),
                "path": str(yaml_file.relative_to(path))
            })
            
        except:
            continue
    
    return {
        "templates": templates[:100],  # 限制返回数量
        "count": len(templates)
    }
