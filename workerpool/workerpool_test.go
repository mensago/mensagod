package workerpool

import (
	"testing"
	"time"
)

func TestWorkerPoolBasic(t *testing.T) {
	p := New(5)

	sampleWorker := func(id uint64) {
		t.Log("Worker sleeping")
		time.Sleep(time.Second * 1)
		p.Done(id)
	}
	if pid, ok := p.Add(); ok {
		go sampleWorker(pid)
	} else {
		t.Fatal("WorkerPool basic test failed to spawn a worker")
	}

	p.Quit()
}

func TestWorkerPoolMulti(t *testing.T) {
	var workerCount uint = 5
	p := New(workerCount)

	sampleWorker := func(id uint64) {
		t.Log("Worker sleeping")
		time.Sleep(time.Second * 1)
		t.Log("Worker preparing to quit")
		p.Done(id)
		t.Log("Worker exiting")
	}

	for i := 0; i < 5; i++ {
		if pid, ok := p.Add(); ok {
			go sampleWorker(pid)
		} else {
			t.Fatal("WorkerPool multi test failed to spawn a worker")
		}
	}

	if _, ok := p.Add(); ok {
		t.Fatal("WorkerPool multi test failed to catch overcapacity spawning")
	}
	p.Quit()
}

func TestWorkerPoolCapReduction(t *testing.T) {
	var workerCount uint = 5
	p := New(workerCount)

	sampleWorker := func(id uint64) {
		t.Log("Worker sleeping")
		time.Sleep(time.Millisecond * 500)
		t.Log("Worker preparing to quit")
		p.Done(id)
		t.Log("Worker exiting")
	}

	for i := 0; i < 5; i++ {
		if pid, ok := p.Add(); ok {
			go sampleWorker(pid)
		} else {
			t.Fatal("WorkerPool overcap test failed to spawn a worker")
		}
	}
	p.SetCapacity(2)
	if _, ok := p.Add(); ok {
		t.Fatal("WorkerPool overcap test failed to catch overcapacity spawning")
	}

	p.Wait()
	if _, ok := p.Add(); !ok {
		t.Fatal("WorkerPool overcap test failed to spawn a new worker")
	}
	p.Quit()
}
