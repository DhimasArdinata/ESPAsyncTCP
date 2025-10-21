#pragma once

#include <cstddef> // For size_t
#include <utility> // For std::is_same, std::declval

template<typename T> class SimpleIntrusiveList {
  // This static_assert ensures that any type 'T' used with this list 
  // MUST have a public member variable 'T* next'.
  static_assert(std::is_same<decltype(std::declval<T>().next), T *>::value, "Template type must have public 'T* next' member");

public:
  typedef T value_type;
  typedef value_type *value_ptr_type;
  typedef value_ptr_type *value_ptr_ptr_type;

  // Constructor and Destructor
  SimpleIntrusiveList() : _head(nullptr), _tail(&_head) {}
  ~SimpleIntrusiveList() {
    clear();
  }

  // This class manages resources (the nodes), so it should be non-copyable and non-movable.
  SimpleIntrusiveList(const SimpleIntrusiveList<T> &) = delete;
  SimpleIntrusiveList(SimpleIntrusiveList<T> &&) = delete;
  SimpleIntrusiveList<T> &operator=(const SimpleIntrusiveList<T> &) = delete;
  SimpleIntrusiveList<T> &operator=(SimpleIntrusiveList<T> &&) = delete;

  inline bool empty() const {
      return _head == nullptr;
  }

  inline void push_back(value_ptr_type obj) {
    if (obj) {
      obj->next = nullptr;
      *_tail = obj;
      _tail = &obj->next;
    }
  }

  inline value_ptr_type pop_front() {
    auto rv = _head;
    if (_head) {
      if (_tail == &_head->next) {
        _tail = &_head;
      }
      _head = _head->next;
    }
    return rv;
  }

  inline void clear() {
    while (_head) {
      auto t = _head;
      _head = _head->next;
      delete t; // Assumes all elements were allocated with "new"
    }
    _head = nullptr;
    _tail = &_head;
  }
};