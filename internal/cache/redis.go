package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrRedisKeyNotFound is returned by Get when the key does not exist.
var ErrRedisKeyNotFound = errors.New("cache: key not found")

type RedisClient struct {
	rdb redis.UniversalClient
}

type Config struct {
	// Addrs is one or more "host:port" strings.
	// Single entry  → standalone / sentinel mode.
	// Multiple entries → cluster mode.
	Addrs    []string
	Password string
	// DB is only used in standalone mode (ignored in cluster mode).
	DB int
}

// NewRedisClient creates a RedisClient and verifies the connection with a PING.
func NewRedisClient(cfg Config) (*RedisClient, error) {
	rdb := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    cfg.Addrs, // If a cluster this Go client automatically handles sharding. Hence, an array.
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("cache.New ping: %w", err)
	}

	return &RedisClient{rdb: rdb}, nil
}

// Set stores value under key with an optional TTL.
// Pass ttl = 0 to store without expiry.
func (c *RedisClient) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	if err := c.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("cache.Set %q: %w", key, err)
	}
	return nil
}

// Get retrieves the string value stored under key.
// Returns ErrRedisKeyNotFound when the key does not exist or has expired.
func (c *RedisClient) Get(ctx context.Context, key string) (string, error) {
	val, err := c.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrRedisKeyNotFound
	}
	if err != nil {
		return "", fmt.Errorf("cache.Get %q: %w", key, err)
	}
	return val, nil
}

// Delete removes one or more keys. Missing keys are silently ignored.
func (c *RedisClient) Delete(ctx context.Context, keys ...string) error {
	if err := c.rdb.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("cache.Delete: %w", err)
	}
	return nil
}

// Exists reports whether the key is present and not expired.
func (c *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("cache.Exists %q: %w", key, err)
	}
	return n > 0, nil
}

// TTL returns the remaining time-to-live of a key.
// Returns 0 if the key has no expiry, ErrRedisKeyNotFound if it does not exist.
func (c *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	d, err := c.rdb.TTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("cache.TTL %q: %w", key, err)
	}
	if d == -2*time.Second { // go-redis returns -2 when key does not exist
		return 0, ErrRedisKeyNotFound
	}
	if d == -1*time.Second { // go-redis returns -1 when key has no expiry
		return 0, nil
	}
	return d, nil
}

// Close releases the underlying connection pool.
func (c *RedisClient) Close() error {
	return c.rdb.Close()
}
