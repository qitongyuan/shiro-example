package com.qty.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.qty.entity.User;
import org.apache.ibatis.annotations.Mapper;

/**
 * @author qty
 * date 2020-02-02
 */
@Mapper
public interface UserMapper extends BaseMapper<User> {
}