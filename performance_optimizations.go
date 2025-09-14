// Performance Optimizations for Handling 1000+ Network Devices
// Includes batch processing, intelligent caching, memory optimization, and concurrency management

package performance

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// PerformanceOptimizer manages system-wide performance optimizations
type PerformanceOptimizer struct {
	config           PerformanceConfig
	batchProcessor   *BatchProcessor
	cacheManager     *IntelligentCacheManager
	memoryManager    *MemoryManager
	concurrencyMgr   *ConcurrencyManager
	loadBalancer     *LoadBalancer
	compressionMgr   *CompressionManager
	metrics          *PerformanceMetrics
	logger           Logger
	mu               sync.RWMutex
}

// PerformanceConfig holds optimization configuration
type PerformanceConfig struct {
	// Batch processing
	MaxBatchSize            int
	BatchTimeoutMs          int
	MaxConcurrentBatches    int
	BatchSizeStrategy       BatchSizeStrategy

	// Memory management
	MaxMemoryUsageMB        int64
	GCTargetPercent         int
	MemoryPressureThreshold float64
	EnableMemoryProfiling   bool

	// Caching
	MaxCacheSize            int64
	CacheEvictionStrategy   EvictionStrategy
	CacheCompressionEnabled bool
	CacheShardCount         int

	// Concurrency
	MaxGoroutines           int
	WorkerPoolSize          int
	ConnectionPoolSize      int
	QueueBufferSize         int

	// Load balancing
	LoadBalancingStrategy   LoadBalancingStrategy
	HealthCheckInterval     time.Duration
	FailoverTimeout         time.Duration

	// Compression
	CompressionLevel        int
	CompressionThreshold    int
	CompressionFormats      []CompressionFormat

	// Performance tuning
	EnableProfiling         bool
	MetricsCollectionInterval time.Duration
	PerformanceTuningEnabled  bool
}

// BatchProcessor handles efficient batch operations on multiple devices
type BatchProcessor struct {
	config           BatchConfig
	activeJobs       map[string]*BatchJob
	jobQueue         chan *BatchJob
	resultAggregator *ResultAggregator
	optimizer        *BatchOptimizer
	metrics          *BatchMetrics
	logger           Logger
	mu               sync.RWMutex
}

// BatchJob represents a batch operation on multiple devices
type BatchJob struct {
	ID             string
	Type           BatchJobType
	Devices        []*NetworkDevice
	Commands       []string
	Parameters     map[string]interface{}
	Context        context.Context
	CreatedAt      time.Time
	StartedAt      time.Time
	CompletedAt    time.Time
	Status         BatchJobStatus
	Progress       *BatchProgress
	Results        []*DeviceResult
	Error          error
	Priority       Priority
	Timeout        time.Duration
	RetryPolicy    *RetryPolicy
	Callbacks      []BatchCallback
}

// IntelligentCacheManager provides advanced caching with compression and sharding
type IntelligentCacheManager struct {
	config          CacheConfig
	shards          []*CacheShard
	shardCount      int
	compressionMgr  *CompressionManager
	evictionPolicy  EvictionPolicy
	metrics         *CacheMetrics
	bloomFilter     *BloomFilter
	logger          Logger
}

// CacheShard represents a single cache shard for better concurrency
type CacheShard struct {
	data            map[string]*CacheEntry
	accessOrder     *AccessOrderTracker
	size            int64
	maxSize         int64
	mu              sync.RWMutex
}

// CacheEntry represents a cached item with metadata
type CacheEntry struct {
	Key           string
	Value         interface{}
	CompressedData []byte
	Size          int64
	CreatedAt     time.Time
	LastAccessed  time.Time
	AccessCount   int64
	TTL           time.Duration
	Compressed    bool
	Hash          uint64
}

// MemoryManager optimizes memory usage across the application
type MemoryManager struct {
	config           MemoryConfig
	stats            *MemoryStats
	allocator        *ObjectPoolAllocator
	garbageCollector *OptimizedGC
	profiler         *MemoryProfiler
	pressureMonitor  *MemoryPressureMonitor
	logger           Logger
}

// ConcurrencyManager optimizes goroutine and resource usage
type ConcurrencyManager struct {
	config              ConcurrencyConfig
	goroutinePool       *GoroutinePool
	semaphores          map[string]*WeightedSemaphore
	rateLimiters        map[string]*TokenBucketLimiter
	backpressureControl *BackpressureController
	loadShedder         *LoadShedder
	metrics             *ConcurrencyMetrics
	logger              Logger
	mu                  sync.RWMutex
}

// LoadBalancer distributes work across available resources
type LoadBalancer struct {
	config      LoadBalancerConfig
	backends    []*Backend
	selector    BackendSelector
	healthCheck *HealthChecker
	metrics     *LoadBalancerMetrics
	logger      Logger
	mu          sync.RWMutex
}

// CompressionManager handles data compression/decompression
type CompressionManager struct {
	config         CompressionConfig
	compressors    map[CompressionFormat]Compressor
	decompressors  map[CompressionFormat]Decompressor
	metrics        *CompressionMetrics
	logger         Logger
}

// PerformanceMetrics tracks system-wide performance
type PerformanceMetrics struct {
	// Throughput metrics
	RequestsPerSecond    float64
	DevicesPerSecond     float64
	CommandsPerSecond    float64
	BytesProcessedPerSec int64

	// Latency metrics
	AverageLatency       time.Duration
	P50Latency           time.Duration
	P95Latency           time.Duration
	P99Latency           time.Duration

	// Resource utilization
	CPUUtilization       float64
	MemoryUtilization    float64
	GoroutineCount       int64
	ConnectionPoolUsage  float64

	// Cache performance
	CacheHitRate         float64
	CacheMissRate        float64
	CacheEvictionRate    float64
	CompressionRatio     float64

	// Error rates
	ErrorRate            float64
	TimeoutRate          float64
	CircuitBreakerRate   float64

	// Batch processing
	AverageBatchSize     float64
	BatchProcessingTime  time.Duration
	BatchSuccessRate     float64

	mu sync.RWMutex
}

// Enums and types
type BatchJobType string
const (
	BatchJobTypeCommand    BatchJobType = "command"
	BatchJobTypeConfig     BatchJobType = "config"
	BatchJobTypeDiscovery  BatchJobType = "discovery"
	BatchJobTypeHealthCheck BatchJobType = "health_check"
)

type BatchJobStatus string
const (
	BatchJobStatusPending    BatchJobStatus = "pending"
	BatchJobStatusRunning    BatchJobStatus = "running"
	BatchJobStatusCompleted  BatchJobStatus = "completed"
	BatchJobStatusFailed     BatchJobStatus = "failed"
	BatchJobStatusCancelled  BatchJobStatus = "cancelled"
)

type BatchSizeStrategy string
const (
	StrategyFixed     BatchSizeStrategy = "fixed"
	StrategyAdaptive  BatchSizeStrategy = "adaptive"
	StrategyOptimal   BatchSizeStrategy = "optimal"
)

type EvictionStrategy string
const (
	EvictionLRU        EvictionStrategy = "lru"
	EvictionLFU        EvictionStrategy = "lfu"
	EvictionTTL        EvictionStrategy = "ttl"
	EvictionAdaptive   EvictionStrategy = "adaptive"
)

type LoadBalancingStrategy string
const (
	LoadBalanceRoundRobin    LoadBalancingStrategy = "round_robin"
	LoadBalanceLeastConn     LoadBalancingStrategy = "least_conn"
	LoadBalanceWeighted      LoadBalancingStrategy = "weighted"
	LoadBalanceLatencyBased  LoadBalancingStrategy = "latency_based"
)

type CompressionFormat string
const (
	CompressionGzip   CompressionFormat = "gzip"
	CompressionZstd   CompressionFormat = "zstd"
	CompressionLZ4    CompressionFormat = "lz4"
	CompressionSnappy CompressionFormat = "snappy"
)

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(config PerformanceConfig, logger Logger) *PerformanceOptimizer {
	optimizer := &PerformanceOptimizer{
		config:  config,
		metrics: &PerformanceMetrics{},
		logger:  logger,
	}

	// Initialize components
	optimizer.batchProcessor = NewBatchProcessor(
		BatchConfig{
			MaxBatchSize:         config.MaxBatchSize,
			TimeoutMs:           config.BatchTimeoutMs,
			MaxConcurrentBatches: config.MaxConcurrentBatches,
			SizeStrategy:        config.BatchSizeStrategy,
		},
		logger,
	)

	optimizer.cacheManager = NewIntelligentCacheManager(
		CacheConfig{
			MaxSize:            config.MaxCacheSize,
			EvictionStrategy:   config.CacheEvictionStrategy,
			CompressionEnabled: config.CacheCompressionEnabled,
			ShardCount:         config.CacheShardCount,
		},
		logger,
	)

	optimizer.memoryManager = NewMemoryManager(
		MemoryConfig{
			MaxUsageMB:           config.MaxMemoryUsageMB,
			GCTargetPercent:      config.GCTargetPercent,
			PressureThreshold:    config.MemoryPressureThreshold,
			ProfilingEnabled:     config.EnableMemoryProfiling,
		},
		logger,
	)

	optimizer.concurrencyMgr = NewConcurrencyManager(
		ConcurrencyConfig{
			MaxGoroutines:      config.MaxGoroutines,
			WorkerPoolSize:     config.WorkerPoolSize,
			ConnectionPoolSize: config.ConnectionPoolSize,
			QueueBufferSize:    config.QueueBufferSize,
		},
		logger,
	)

	optimizer.loadBalancer = NewLoadBalancer(
		LoadBalancerConfig{
			Strategy:            config.LoadBalancingStrategy,
			HealthCheckInterval: config.HealthCheckInterval,
			FailoverTimeout:     config.FailoverTimeout,
		},
		logger,
	)

	optimizer.compressionMgr = NewCompressionManager(
		CompressionConfig{
			Level:     config.CompressionLevel,
			Threshold: config.CompressionThreshold,
			Formats:   config.CompressionFormats,
		},
		logger,
	)

	// Start monitoring and optimization routines
	optimizer.startOptimizationRoutines()

	return optimizer
}

// ProcessDeviceBatch processes a batch of devices with optimal performance
func (p *PerformanceOptimizer) ProcessDeviceBatch(ctx context.Context, devices []*NetworkDevice, commands []string, options BatchOptions) (*BatchResult, error) {
	startTime := time.Now()

	// Optimize batch size based on current system load
	optimalBatches := p.calculateOptimalBatching(devices, commands)

	p.logger.Info("Processing device batch",
		"total_devices", len(devices),
		"commands", len(commands),
		"optimal_batches", len(optimalBatches),
	)

	var results []*DeviceBatchResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process batches concurrently
	semaphore := make(chan struct{}, p.config.MaxConcurrentBatches)

	for i, batch := range optimalBatches {
		wg.Add(1)
		go func(batchIndex int, deviceBatch []*NetworkDevice) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Process batch
			batchResult := p.processSingleBatch(ctx, deviceBatch, commands, batchIndex)

			// Store result
			mu.Lock()
			results = append(results, batchResult)
			mu.Unlock()

		}(i, batch)
	}

	wg.Wait()

	// Aggregate results
	aggregatedResult := p.aggregateBatchResults(results)
	aggregatedResult.Duration = time.Since(startTime)

	// Update performance metrics
	p.updatePerformanceMetrics(aggregatedResult)

	return aggregatedResult, nil
}

// calculateOptimalBatching determines optimal batch sizes based on system state
func (p *PerformanceOptimizer) calculateOptimalBatching(devices []*NetworkDevice, commands []string) [][]*NetworkDevice {
	// Group devices by characteristics for optimal batching
	deviceGroups := p.groupDevicesByCharacteristics(devices)

	var batches [][]*NetworkDevice

	for _, group := range deviceGroups {
		// Calculate optimal batch size for this group
		optimalSize := p.calculateOptimalBatchSize(group, commands)

		// Create batches from the group
		groupBatches := p.createBatchesFromGroup(group, optimalSize)
		batches = append(batches, groupBatches...)
	}

	return batches
}

// groupDevicesByCharacteristics groups devices by similar characteristics
func (p *PerformanceOptimizer) groupDevicesByCharacteristics(devices []*NetworkDevice) map[string][]*NetworkDevice {
	groups := make(map[string][]*NetworkDevice)

	for _, device := range devices {
		// Create grouping key based on device characteristics
		key := fmt.Sprintf("%s_%s_%s",
			device.Vendor,
			device.Model,
			device.Location,  // Assuming location affects network latency
		)

		groups[key] = append(groups[key], device)
	}

	return groups
}

// calculateOptimalBatchSize determines the optimal batch size for a group
func (p *PerformanceOptimizer) calculateOptimalBatchSize(devices []*NetworkDevice, commands []string) int {
	// Base batch size
	baseSize := p.config.MaxBatchSize

	// Adjust based on current system load
	cpuUsage := p.getCurrentCPUUsage()
	memUsage := p.getCurrentMemoryUsage()

	adjustmentFactor := 1.0

	// Reduce batch size if system is under pressure
	if cpuUsage > 0.8 {
		adjustmentFactor *= 0.7
	}
	if memUsage > 0.8 {
		adjustmentFactor *= 0.8
	}

	// Adjust based on command complexity
	commandComplexity := p.estimateCommandComplexity(commands)
	if commandComplexity > 0.7 {
		adjustmentFactor *= 0.8
	}

	// Adjust based on device responsiveness (historical data)
	avgResponseTime := p.getAverageResponseTime(devices)
	if avgResponseTime > 5*time.Second {
		adjustmentFactor *= 0.6
	}

	optimalSize := int(float64(baseSize) * adjustmentFactor)

	// Ensure minimum batch size
	if optimalSize < 5 {
		optimalSize = 5
	}

	// Ensure maximum batch size
	if optimalSize > len(devices) {
		optimalSize = len(devices)
	}

	return optimalSize
}

// processSingleBatch processes a single batch of devices
func (p *PerformanceOptimizer) processSingleBatch(ctx context.Context, devices []*NetworkDevice, commands []string, batchIndex int) *DeviceBatchResult {
	startTime := time.Now()

	result := &DeviceBatchResult{
		BatchIndex:    batchIndex,
		DeviceCount:   len(devices),
		CommandCount:  len(commands),
		StartTime:     startTime,
		DeviceResults: make([]*DeviceResult, 0, len(devices)),
	}

	// Sort devices by priority/response time for optimal processing order
	sortedDevices := p.sortDevicesByOptimalOrder(devices)

	// Process devices in the batch
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Use semaphore to limit concurrent connections per batch
	maxConcurrent := min(len(devices), p.config.ConnectionPoolSize/p.config.MaxConcurrentBatches)
	semaphore := make(chan struct{}, maxConcurrent)

	for _, device := range sortedDevices {
		wg.Add(1)
		go func(dev *NetworkDevice) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Process single device
			deviceResult := p.processSingleDevice(ctx, dev, commands)

			// Store result
			mu.Lock()
			result.DeviceResults = append(result.DeviceResults, deviceResult)
			mu.Unlock()

		}(device)
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Calculate batch statistics
	p.calculateBatchStatistics(result)

	return result
}

// processSingleDevice processes commands on a single device with optimizations
func (p *PerformanceOptimizer) processSingleDevice(ctx context.Context, device *NetworkDevice, commands []string) *DeviceResult {
	startTime := time.Now()

	result := &DeviceResult{
		DeviceID:       device.ID,
		Hostname:       device.Hostname,
		StartTime:      startTime,
		CommandResults: make([]*CommandResult, 0, len(commands)),
	}

	// Check cache for recent results
	cacheKey := p.generateDeviceCacheKey(device, commands)
	if cached := p.cacheManager.Get(cacheKey); cached != nil {
		p.logger.Debug("Using cached result for device", "device", device.Hostname)
		return cached.(*DeviceResult)
	}

	// Get optimized connection
	conn, err := p.getOptimizedConnection(ctx, device)
	if err != nil {
		result.Error = err
		result.Status = DeviceStatusFailed
		return result
	}
	defer p.returnConnection(conn)

	// Execute commands with optimal batching
	optimizedCommands := p.optimizeCommandExecution(commands, device)

	for _, cmd := range optimizedCommands {
		cmdResult := p.executeOptimizedCommand(ctx, conn, cmd)
		result.CommandResults = append(result.CommandResults, cmdResult)

		// Break on first error if configured
		if cmdResult.Error != nil && !p.config.ContinueOnError {
			result.Error = cmdResult.Error
			break
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Determine overall status
	if result.Error == nil {
		result.Status = DeviceStatusSuccess
	} else {
		result.Status = DeviceStatusFailed
	}

	// Cache successful results
	if result.Status == DeviceStatusSuccess {
		p.cacheManager.Set(cacheKey, result, 5*time.Minute)
	}

	return result
}

// Memory optimization methods
func (p *PerformanceOptimizer) OptimizeMemoryUsage() {
	// Force garbage collection if memory pressure is high
	if p.memoryManager.IsUnderPressure() {
		runtime.GC()

		// Clear non-essential caches
		p.cacheManager.EvictLeastUsed(0.3) // Evict 30% of cache

		p.logger.Info("Performed memory optimization due to pressure")
	}

	// Optimize object pools
	p.memoryManager.OptimizeObjectPools()

	// Tune GC settings based on current load
	p.memoryManager.TuneGarbageCollector()
}

// Connection pool optimization
func (p *PerformanceOptimizer) getOptimizedConnection(ctx context.Context, device *NetworkDevice) (Connection, error) {
	// Get connection with load balancing and health checking
	backend := p.loadBalancer.SelectOptimalBackend(device)
	if backend == nil {
		return nil, fmt.Errorf("no healthy backend available for device %s", device.Hostname)
	}

	// Use connection pooling with optimal settings
	return backend.GetConnection(ctx, device)
}

// Command execution optimization
func (p *PerformanceOptimizer) optimizeCommandExecution(commands []string, device *NetworkDevice) []OptimizedCommand {
	var optimized []OptimizedCommand

	// Group similar commands
	commandGroups := p.groupSimilarCommands(commands)

	// Optimize each group
	for _, group := range commandGroups {
		if p.canBatchCommands(group, device) {
			// Create batch command
			batchCmd := p.createBatchCommand(group)
			optimized = append(optimized, batchCmd)
		} else {
			// Execute individually
			for _, cmd := range group {
				optimized = append(optimized, OptimizedCommand{
					Command: cmd,
					Batch:   false,
				})
			}
		}
	}

	return optimized
}

// Performance monitoring and auto-tuning
func (p *PerformanceOptimizer) startOptimizationRoutines() {
	// Performance metrics collection
	go p.collectPerformanceMetrics()

	// Auto-tuning based on metrics
	go p.autoTunePerformance()

	// Memory pressure monitoring
	go p.monitorMemoryPressure()

	// Connection pool optimization
	go p.optimizeConnectionPools()

	// Cache optimization
	go p.optimizeCaching()
}

// Placeholder data structures and methods
type NetworkDevice struct {
	ID       int
	Hostname string
	Vendor   string
	Model    string
	Location string
}

type BatchOptions struct{}
type BatchResult struct {
	Duration time.Duration
}
type DeviceBatchResult struct {
	BatchIndex    int
	DeviceCount   int
	CommandCount  int
	StartTime     time.Time
	EndTime       time.Time
	Duration      time.Duration
	DeviceResults []*DeviceResult
}

type DeviceResult struct {
	DeviceID       int
	Hostname       string
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
	Status         DeviceStatus
	Error          error
	CommandResults []*CommandResult
}

type DeviceStatus string
const (
	DeviceStatusSuccess DeviceStatus = "success"
	DeviceStatusFailed  DeviceStatus = "failed"
)

type CommandResult struct {
	Error error
}

type Connection interface{}
type OptimizedCommand struct {
	Command string
	Batch   bool
}

// Additional configuration structures
type BatchConfig struct {
	MaxBatchSize         int
	TimeoutMs           int
	MaxConcurrentBatches int
	SizeStrategy        BatchSizeStrategy
}

type CacheConfig struct {
	MaxSize            int64
	EvictionStrategy   EvictionStrategy
	CompressionEnabled bool
	ShardCount         int
}

type MemoryConfig struct {
	MaxUsageMB        int64
	GCTargetPercent   int
	PressureThreshold float64
	ProfilingEnabled  bool
}

type ConcurrencyConfig struct {
	MaxGoroutines      int
	WorkerPoolSize     int
	ConnectionPoolSize int
	QueueBufferSize    int
}

type LoadBalancerConfig struct {
	Strategy            LoadBalancingStrategy
	HealthCheckInterval time.Duration
	FailoverTimeout     time.Duration
}

type CompressionConfig struct {
	Level     int
	Threshold int
	Formats   []CompressionFormat
}

// Placeholder method implementations
func NewBatchProcessor(config BatchConfig, logger Logger) *BatchProcessor { return &BatchProcessor{} }
func NewIntelligentCacheManager(config CacheConfig, logger Logger) *IntelligentCacheManager { return &IntelligentCacheManager{} }
func NewMemoryManager(config MemoryConfig, logger Logger) *MemoryManager { return &MemoryManager{} }
func NewConcurrencyManager(config ConcurrencyConfig, logger Logger) *ConcurrencyManager { return &ConcurrencyManager{} }
func NewLoadBalancer(config LoadBalancerConfig, logger Logger) *LoadBalancer { return &LoadBalancer{} }
func NewCompressionManager(config CompressionConfig, logger Logger) *CompressionManager { return &CompressionManager{} }

func (p *PerformanceOptimizer) startOptimizationRoutines() {}
func (p *PerformanceOptimizer) createBatchesFromGroup(group []*NetworkDevice, size int) [][]*NetworkDevice { return nil }
func (p *PerformanceOptimizer) getCurrentCPUUsage() float64 { return 0.5 }
func (p *PerformanceOptimizer) getCurrentMemoryUsage() float64 { return 0.5 }
func (p *PerformanceOptimizer) estimateCommandComplexity(commands []string) float64 { return 0.5 }
func (p *PerformanceOptimizer) getAverageResponseTime(devices []*NetworkDevice) time.Duration { return time.Second }
func (p *PerformanceOptimizer) sortDevicesByOptimalOrder(devices []*NetworkDevice) []*NetworkDevice { return devices }
func (p *PerformanceOptimizer) calculateBatchStatistics(result *DeviceBatchResult) {}
func (p *PerformanceOptimizer) generateDeviceCacheKey(device *NetworkDevice, commands []string) string { return "key" }
func (p *PerformanceOptimizer) returnConnection(conn Connection) {}
func (p *PerformanceOptimizer) executeOptimizedCommand(ctx context.Context, conn Connection, cmd OptimizedCommand) *CommandResult { return &CommandResult{} }
func (p *PerformanceOptimizer) aggregateBatchResults(results []*DeviceBatchResult) *BatchResult { return &BatchResult{} }
func (p *PerformanceOptimizer) updatePerformanceMetrics(result *BatchResult) {}
func (p *PerformanceOptimizer) groupSimilarCommands(commands []string) [][]string { return nil }
func (p *PerformanceOptimizer) canBatchCommands(group []string, device *NetworkDevice) bool { return false }
func (p *PerformanceOptimizer) createBatchCommand(group []string) OptimizedCommand { return OptimizedCommand{} }
func (p *PerformanceOptimizer) collectPerformanceMetrics() {}
func (p *PerformanceOptimizer) autoTunePerformance() {}
func (p *PerformanceOptimizer) monitorMemoryPressure() {}
func (p *PerformanceOptimizer) optimizeConnectionPools() {}
func (p *PerformanceOptimizer) optimizeCaching() {}

func (cm *IntelligentCacheManager) Get(key string) interface{} { return nil }
func (cm *IntelligentCacheManager) Set(key string, value interface{}, ttl time.Duration) {}
func (cm *IntelligentCacheManager) EvictLeastUsed(percentage float64) {}

func (mm *MemoryManager) IsUnderPressure() bool { return false }
func (mm *MemoryManager) OptimizeObjectPools() {}
func (mm *MemoryManager) TuneGarbageCollector() {}

func (lb *LoadBalancer) SelectOptimalBackend(device *NetworkDevice) *Backend { return nil }

type Backend struct{}
func (b *Backend) GetConnection(ctx context.Context, device *NetworkDevice) (Connection, error) { return nil, nil }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}