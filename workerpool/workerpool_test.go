package workerpool

import (
	"testing"
	"time"
)

func TestWorkerPoolBasic(t *testing.T) {
	p := New(5)

	sampleWorker := func() {
		t.Log("Worker sleeping")
		time.Sleep(time.Second * 30)
		p.Done()
	}
	if p.Add(1) > 0 {
		go sampleWorker()
	} else {
		t.Fatal("WorkerPool multi test failed to spawn a worker")
	}

	p.Quit()
}

func TestWorkerPoolMulti(t *testing.T) {
	var workerCount uint = 5
	p := New(workerCount)

	sampleWorker := func() {
		t.Log("Worker sleeping")
		time.Sleep(time.Second * 1)
		t.Log("Worker preparing to quit")
		p.Done()
		t.Log("Worker exiting")
	}

	for i := 0; i < 5; i++ {
		if p.Add(1) > 0 {
			go sampleWorker()
		} else {
			t.Fatal("WorkerPool multi test failed to spawn a worker")
		}
	}

	if p.Add(2) > 0 {
		t.Fatal("WorkerPool multi test failed to catch overcapacity spawning")
	}
	p.Quit()
}

func TestWorkerPoolCapReduction(t *testing.T) {
	var workerCount uint = 5
	p := New(workerCount)

	sampleWorker := func() {
		t.Log("Worker sleeping")
		time.Sleep(time.Millisecond * 500)
		t.Log("Worker preparing to quit")
		p.Done()
		t.Log("Worker exiting")
	}

	for i := 0; i < 5; i++ {
		if p.Add(1) > 0 {
			go sampleWorker()
		} else {
			t.Fatal("WorkerPool overcap test failed to spawn a worker")
		}
	}
	p.SetCapacity(2)
	if p.Add(1) > 0 {
		t.Fatal("WorkerPool overcap test failed to catch overcapacity spawning")
	}

	p.Wait()
	if p.Add(1) < 1 {
		t.Fatal("WorkerPool overcap test failed to spawn a new worker")
	}
	p.Quit()
}
