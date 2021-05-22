// This package creates a very simple pool of goroutines. Sometimes a channel is not appropriate.
// There are probably more efficient ways of implementing this, but it is simple and works well.
package workerpool

import (
	"sync"
)

type Pool struct {
	workerCount uint
	workerGroup sync.WaitGroup
	capacity    uint
	workerLock  sync.Mutex
	quitFlag    bool
	quitLock    sync.RWMutex
}

// New creates a new worker pool with the specified capacity
func New(capacity uint) *Pool {
	var out Pool
	out.SetCapacity(capacity)
	return &out
}

// SetCapacity adjusts the capacity of the Pool. If set lower than the current number of workers,
// calls to Add will return 0 until the number of workes becomes less than the capacity
func (p *Pool) SetCapacity(capacity uint) {
	p.capacity = capacity
}

func (p *Pool) Add(count uint) uint {
	p.workerLock.Lock()
	defer p.workerLock.Unlock()

	if p.workerCount+count <= p.capacity {
		p.workerCount += count
		p.workerGroup.Add(int(count))
	} else {
		return 0
	}

	return count
}

// Done is called by worker goroutines to signify they are quitting
func (p *Pool) Done() {
	p.workerLock.Lock()
	defer p.workerLock.Unlock()

	p.workerCount--
	p.workerGroup.Done()
}

func (p *Pool) Quit() {
	p.quitLock.Lock()
	p.quitFlag = true
	p.quitLock.Unlock()
	p.workerGroup.Wait()
}

func (p *Pool) IsQuitting() bool {
	p.quitLock.RLock()
	defer p.quitLock.RUnlock()

	out := p.quitFlag
	return out
}
