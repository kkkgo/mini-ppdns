package list

import "testing"

func TestNewElem(t *testing.T) {
	e := NewElem(42)
	if e.Value != 42 {
		t.Fatalf("value = %d, want 42", e.Value)
	}
	if e.Prev() != nil || e.Next() != nil {
		t.Fatal("new elem should have nil prev/next")
	}
}

func TestList_PushFront(t *testing.T) {
	l := New[int]()
	e1 := l.PushFront(NewElem(1))
	if l.Len() != 1 {
		t.Fatalf("len = %d, want 1", l.Len())
	}
	if l.Front() != e1 || l.Back() != e1 {
		t.Fatal("single elem should be both front and back")
	}

	e2 := l.PushFront(NewElem(2))
	if l.Len() != 2 {
		t.Fatalf("len = %d, want 2", l.Len())
	}
	if l.Front() != e2 {
		t.Fatal("front should be e2")
	}
	if l.Back() != e1 {
		t.Fatal("back should be e1")
	}
	if e2.Next() != e1 {
		t.Fatal("e2.Next should be e1")
	}
	if e1.Prev() != e2 {
		t.Fatal("e1.Prev should be e2")
	}
}

func TestList_PushBack(t *testing.T) {
	l := New[string]()
	e1 := l.PushBack(NewElem("a"))
	e2 := l.PushBack(NewElem("b"))
	e3 := l.PushBack(NewElem("c"))

	if l.Len() != 3 {
		t.Fatalf("len = %d, want 3", l.Len())
	}
	if l.Front() != e1 {
		t.Fatal("front should be e1")
	}
	if l.Back() != e3 {
		t.Fatal("back should be e3")
	}

	// verify order: e1 -> e2 -> e3
	if e1.Next() != e2 || e2.Next() != e3 {
		t.Fatal("forward links broken")
	}
	if e3.Prev() != e2 || e2.Prev() != e1 {
		t.Fatal("backward links broken")
	}
}

func TestList_PopElem_Middle(t *testing.T) {
	l := New[int]()
	e1 := l.PushBack(NewElem(1))
	e2 := l.PushBack(NewElem(2))
	e3 := l.PushBack(NewElem(3))

	l.PopElem(e2)

	if l.Len() != 2 {
		t.Fatalf("len = %d, want 2", l.Len())
	}
	if e1.Next() != e3 {
		t.Fatal("e1.Next should be e3")
	}
	if e3.Prev() != e1 {
		t.Fatal("e3.Prev should be e1")
	}
	// popped elem should be free
	if e2.Prev() != nil || e2.Next() != nil {
		t.Fatal("popped elem should have nil pointers")
	}
}

func TestList_PopElem_Front(t *testing.T) {
	l := New[int]()
	e1 := l.PushBack(NewElem(1))
	e2 := l.PushBack(NewElem(2))

	l.PopElem(e1)

	if l.Front() != e2 || l.Back() != e2 {
		t.Fatal("e2 should be only elem")
	}
	if l.Len() != 1 {
		t.Fatalf("len = %d, want 1", l.Len())
	}
}

func TestList_PopElem_Back(t *testing.T) {
	l := New[int]()
	e1 := l.PushBack(NewElem(1))
	e2 := l.PushBack(NewElem(2))

	l.PopElem(e2)

	if l.Front() != e1 || l.Back() != e1 {
		t.Fatal("e1 should be only elem")
	}
}

func TestList_PopElem_Single(t *testing.T) {
	l := New[int]()
	e := l.PushBack(NewElem(1))
	l.PopElem(e)

	if l.Len() != 0 {
		t.Fatalf("len = %d, want 0", l.Len())
	}
	if l.Front() != nil || l.Back() != nil {
		t.Fatal("empty list should have nil front/back")
	}
}

func TestList_PushFront_PanicsOnUsedElem(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	l := New[int]()
	e := NewElem(1)
	l.PushFront(e)
	l.PushFront(e) // should panic
}

func TestList_PopElem_PanicsOnWrongList(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	l1 := New[int]()
	l2 := New[int]()
	e := NewElem(1)
	l1.PushBack(e)
	l2.PopElem(e) // should panic
}

func TestList_EmptyList(t *testing.T) {
	l := New[int]()
	if l.Len() != 0 {
		t.Fatalf("len = %d, want 0", l.Len())
	}
	if l.Front() != nil || l.Back() != nil {
		t.Fatal("empty list should return nil")
	}
}

func TestList_ReinsertAfterPop(t *testing.T) {
	l := New[int]()
	e := NewElem(1)
	l.PushBack(e)
	l.PopElem(e)
	// should be reinsertable
	l.PushFront(e)
	if l.Len() != 1 || l.Front() != e {
		t.Fatal("re-insert failed")
	}
}
