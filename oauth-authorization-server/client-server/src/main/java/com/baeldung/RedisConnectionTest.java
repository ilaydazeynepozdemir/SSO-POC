package com.baeldung;

import jakarta.annotation.PostConstruct;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;


@Component
public class RedisConnectionTest {

    private final RedisTemplate<String, String> redisTemplate;

    public RedisConnectionTest(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @PostConstruct
    public void testRedisConnection() {
        try {
            RedisConnection connection = redisTemplate.getConnectionFactory().getConnection();
            connection.ping();
            System.out.println("✅ Redis bağlantısı başarılı!");
        } catch (Exception e) {
            System.err.println("❌ Redis bağlantı hatası: " + e.getMessage());
        }
    }
}
