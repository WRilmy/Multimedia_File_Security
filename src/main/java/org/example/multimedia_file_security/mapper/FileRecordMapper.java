package org.example.multimedia_file_security.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.example.multimedia_file_security.pojo.FileRecord;

import java.util.List;

@Mapper
public interface FileRecordMapper extends BaseMapper<FileRecord> {

    // 根据用户ID查询文件列表
    List<FileRecord> selectByUserId(@Param("userId") Long userId);

    // 根据加密文件名查找文件
    FileRecord selectByEncryptedFilename(@Param("encryptedFilename") String encryptedFilename);

    // 更新下载次数
    int updateDownloadCount(@Param("id") Long id);

    // 根据文件类型统计数量
    Integer countByFileType(@Param("userId") Long userId, @Param("fileType") String fileType);
}