"""
Project Manager Module

This module provides project management functionality for ida-graphy.
Projects allow users to organize multiple binary files into cohesive analysis tasks
with dedicated Neo4j databases and persistent metadata.

Key Features:
- Project creation/deletion with automatic Neo4j database management
- Binary file addition/removal with change tracking
- Metadata persistence using JSON + CSV cache storage
- File modification detection using SHA256 hashes
- Project listing and status reporting

Architecture:
- Each project gets its own directory under projects/
- Project metadata stored as project.json
- Analysis results cached as CSV files
- Each project maps to a dedicated Neo4j database
"""

import os
import hashlib
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Tuple
import logging

from .models import ProjectMetadata, BinaryFile, GraphData

logger = logging.getLogger(__name__)


class ProjectError(Exception):
    """项目管理相关异常"""
    pass


class ProjectManager:
    """项目管理器"""
    
    def __init__(self, projects_root: str = "projects"):
        """
        初始化项目管理器
        
        Args:
            projects_root: 项目根目录路径，默认为 "projects"
        """
        self.projects_root = Path(projects_root).absolute()
        self.projects_root.mkdir(exist_ok=True)
        
    def _get_project_dir(self, project_name: str) -> Path:
        """获取项目目录路径"""
        return self.projects_root / project_name
    
    def _get_project_file(self, project_name: str) -> Path:
        """获取项目元数据文件路径"""
        return self._get_project_dir(project_name) / "project.json"
    
    def _get_csv_cache_dir(self, project_name: str) -> Path:
        """获取CSV缓存目录路径"""
        return self._get_project_dir(project_name) / "csv_cache"
    
    def _get_binaries_dir(self, project_name: str) -> Path:
        """获取二进制文件信息目录路径"""
        return self._get_project_dir(project_name) / "binaries"
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """计算文件SHA256哈希"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise ProjectError(f"无法计算文件哈希: {file_path}, 错误: {e}")
    
    def _get_file_stats(self, file_path: str) -> Tuple[int, str]:
        """获取文件统计信息：大小和修改时间"""
        try:
            stat = os.stat(file_path)
            size = stat.st_size
            # 转换为ISO格式时间字符串
            mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()
            return size, mtime
        except Exception as e:
            raise ProjectError(f"无法获取文件统计信息: {file_path}, 错误: {e}")
    
    def create_project(self, project_name: str, description: str = "", 
                      config_overrides: Optional[Dict] = None,
                      config: Optional[Dict] = None) -> ProjectMetadata:
        """
        创建新项目
        
        Args:
            project_name: 项目名称，用作目录名和数据库名的基础
            description: 项目描述，可选
            config_overrides: 项目级配置覆盖，可选
            config: 全局配置，用于获取数据库前缀，可选
            
        Returns:
            创建的项目元数据
            
        Raises:
            ProjectError: 项目已存在或创建失败
        """
        if not project_name or not project_name.replace('_', '').replace('-', '').isalnum():
            raise ProjectError("项目名称只能包含字母、数字、下划线和连字符")
        
        project_dir = self._get_project_dir(project_name)
        if project_dir.exists():
            raise ProjectError(f"项目 '{project_name}' 已存在")
        
        # 创建项目目录结构
        project_dir.mkdir(parents=True)
        self._get_csv_cache_dir(project_name).mkdir()
        self._get_binaries_dir(project_name).mkdir()
        
        # 创建项目元数据
        now = datetime.now().isoformat()
        
        # 使用配置中的数据库前缀，如果没有配置则使用默认值
        if config and 'neo4j' in config and 'projects' in config['neo4j']:
            database_prefix = config['neo4j']['projects'].get('database_prefix', 'idg-project-')
        else:
            database_prefix = 'idg-project-'
            
        database_name = f"{database_prefix}{project_name}"
        
        metadata = ProjectMetadata(
            name=project_name,
            description=description,
            created_time=now,
            modified_time=now,
            database_name=database_name,
            config_overrides=config_overrides or {}
        )
        
        # 保存项目元数据
        try:
            metadata.save_to_file(str(self._get_project_file(project_name)))
            logger.info(f"项目 '{project_name}' 创建成功，数据库: {database_name}")
            return metadata
        except Exception as e:
            # 清理失败的项目目录
            if project_dir.exists():
                shutil.rmtree(project_dir)
            raise ProjectError(f"创建项目失败: {e}")
    
    def delete_project(self, project_name: str, force: bool = False) -> None:
        """
        删除项目
        
        Args:
            project_name: 项目名称
            force: 是否强制删除，忽略错误
            
        Raises:
            ProjectError: 项目不存在或删除失败
        """
        project_dir = self._get_project_dir(project_name)
        if not project_dir.exists():
            if not force:
                raise ProjectError(f"项目 '{project_name}' 不存在")
            return
        
        try:
            # 删除项目目录
            shutil.rmtree(project_dir)
            logger.info(f"项目 '{project_name}' 删除成功")
        except Exception as e:
            if not force:
                raise ProjectError(f"删除项目失败: {e}")
            logger.warning(f"强制删除项目时出现错误: {e}")
    
    def list_projects(self) -> List[ProjectMetadata]:
        """
        列出所有项目
        
        Returns:
            项目元数据列表
        """
        projects = []
        if not self.projects_root.exists():
            return projects
            
        for project_dir in self.projects_root.iterdir():
            if project_dir.is_dir():
                project_file = project_dir / "project.json"
                if project_file.exists():
                    try:
                        metadata = ProjectMetadata.load_from_file(str(project_file))
                        projects.append(metadata)
                    except Exception as e:
                        logger.warning(f"无法加载项目元数据: {project_dir.name}, 错误: {e}")
        
        return sorted(projects, key=lambda p: p.created_time)
    
    def get_project(self, project_name: str) -> ProjectMetadata:
        """
        获取项目元数据
        
        Args:
            project_name: 项目名称
            
        Returns:
            项目元数据
            
        Raises:
            ProjectError: 项目不存在
        """
        project_file = self._get_project_file(project_name)
        if not project_file.exists():
            raise ProjectError(f"项目 '{project_name}' 不存在")
        
        try:
            return ProjectMetadata.load_from_file(str(project_file))
        except Exception as e:
            raise ProjectError(f"加载项目元数据失败: {e}")
    
    def add_binary(self, project_name: str, binary_path: str) -> BinaryFile:
        """
        向项目添加二进制文件
        
        Args:
            project_name: 项目名称
            binary_path: 二进制文件路径
            
        Returns:
            添加的二进制文件信息
            
        Raises:
            ProjectError: 项目不存在、文件不存在或添加失败
        """
        # 检查项目是否存在
        metadata = self.get_project(project_name)
        
        # 检查文件是否存在
        binary_path = os.path.abspath(binary_path)
        if not os.path.exists(binary_path):
            raise ProjectError(f"文件不存在: {binary_path}")
        
        # 计算文件信息
        file_hash = self._calculate_file_hash(binary_path)
        size, modified_time = self._get_file_stats(binary_path)
        file_name = os.path.basename(binary_path)
        
        # 检查文件是否已在项目中
        for existing in metadata.binaries:
            if existing.path == binary_path:
                raise ProjectError(f"文件已在项目中: {binary_path}")
            if existing.hash == file_hash and existing.name == file_name:
                raise ProjectError(f"相同内容的文件已在项目中: {existing.path}")
        
        # 创建二进制文件记录
        now = datetime.now().isoformat()
        binary_file = BinaryFile(
            path=binary_path,
            name=file_name,
            hash=file_hash,
            added_time=now,
            last_modified=modified_time,
            size=size
        )
        
        # 更新项目元数据
        metadata.binaries.append(binary_file)
        metadata.modified_time = now
        
        # 保存更新后的元数据
        try:
            metadata.save_to_file(str(self._get_project_file(project_name)))
            logger.info(f"文件 '{binary_path}' 已添加到项目 '{project_name}'")
            return binary_file
        except Exception as e:
            raise ProjectError(f"保存项目元数据失败: {e}")
    
    def remove_binary(self, project_name: str, binary_path: str) -> None:
        """
        从项目中移除二进制文件
        
        Args:
            project_name: 项目名称
            binary_path: 二进制文件路径
            
        Raises:
            ProjectError: 项目不存在或文件不在项目中
        """
        # 检查项目是否存在
        metadata = self.get_project(project_name)
        
        # 查找要移除的文件
        binary_path = os.path.abspath(binary_path)
        binary_to_remove = None
        for binary in metadata.binaries:
            if binary.path == binary_path:
                binary_to_remove = binary
                break
        
        if not binary_to_remove:
            raise ProjectError(f"文件不在项目中: {binary_path}")
        
        # 移除文件记录
        metadata.binaries.remove(binary_to_remove)
        metadata.modified_time = datetime.now().isoformat()
        
        # 保存更新后的元数据
        try:
            metadata.save_to_file(str(self._get_project_file(project_name)))
            logger.info(f"文件 '{binary_path}' 已从项目 '{project_name}' 中移除")
        except Exception as e:
            raise ProjectError(f"保存项目元数据失败: {e}")
    
    def check_file_changes(self, project_name: str) -> List[Tuple[BinaryFile, str]]:
        """
        检查项目中文件的变化
        
        Args:
            project_name: 项目名称
            
        Returns:
            变化列表，每个元素为(BinaryFile, 变化类型)
            变化类型: 'missing', 'modified', 'unchanged'
        """
        metadata = self.get_project(project_name)
        changes = []
        
        for binary in metadata.binaries:
            if not os.path.exists(binary.path):
                changes.append((binary, 'missing'))
                continue
            
            try:
                current_hash = self._calculate_file_hash(binary.path)
                if current_hash != binary.hash:
                    changes.append((binary, 'modified'))
                else:
                    changes.append((binary, 'unchanged'))
            except Exception as e:
                logger.warning(f"检查文件变化时出错: {binary.path}, 错误: {e}")
                changes.append((binary, 'missing'))
        
        return changes
    
    def update_binary_analysis_time(self, project_name: str, binary_path: str) -> None:
        """
        更新二进制文件的分析时间
        
        Args:
            project_name: 项目名称
            binary_path: 二进制文件路径
        """
        metadata = self.get_project(project_name)
        binary_path = os.path.abspath(binary_path)
        
        for binary in metadata.binaries:
            if binary.path == binary_path:
                binary.last_analyzed = datetime.now().isoformat()
                metadata.modified_time = datetime.now().isoformat()
                metadata.save_to_file(str(self._get_project_file(project_name)))
                break
    
    def get_csv_cache_path(self, project_name: str) -> str:
        """获取项目CSV缓存目录路径"""
        return str(self._get_csv_cache_dir(project_name))
    
    def clear_csv_cache(self, project_name: str) -> None:
        """清空项目的CSV缓存"""
        csv_dir = self._get_csv_cache_dir(project_name)
        if csv_dir.exists():
            shutil.rmtree(csv_dir)
            csv_dir.mkdir()


class Project:
    """项目操作类，提供单个项目的高级操作接口"""
    
    def __init__(self, project_name: str, manager: Optional[ProjectManager] = None):
        """
        初始化项目操作对象
        
        Args:
            project_name: 项目名称
            manager: 项目管理器实例，如果为None则创建默认实例
        """
        self.name = project_name
        self.manager = manager or ProjectManager()
        self._metadata = None
    
    @property
    def metadata(self) -> ProjectMetadata:
        """获取项目元数据（缓存）"""
        if self._metadata is None:
            self._metadata = self.manager.get_project(self.name)
        return self._metadata
    
    def refresh_metadata(self) -> ProjectMetadata:
        """刷新项目元数据缓存"""
        self._metadata = self.manager.get_project(self.name)
        return self._metadata
    
    @property
    def database_name(self) -> str:
        """获取项目对应的数据库名"""
        return self.metadata.database_name
    
    def get_binary_files(self) -> List[BinaryFile]:
        """获取项目中的所有二进制文件"""
        return self.metadata.binaries
    
    def has_binary(self, binary_path: str) -> bool:
        """检查项目是否包含指定的二进制文件"""
        binary_path = os.path.abspath(binary_path)
        for binary in self.metadata.binaries:
            if binary.path == binary_path:
                return True
        return False
    
    def get_changed_files(self) -> List[BinaryFile]:
        """获取已变更的文件列表"""
        changes = self.manager.check_file_changes(self.name)
        return [binary for binary, status in changes if status in ('modified', 'missing')]
    
    def needs_sync(self) -> bool:
        """检查项目是否需要同步（有变更的文件或未分析的文件）"""
        for binary in self.metadata.binaries:
            if binary.last_analyzed is None:
                return True
        return len(self.get_changed_files()) > 0