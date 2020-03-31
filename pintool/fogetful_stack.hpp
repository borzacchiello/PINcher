#ifndef FORGETFULSTACK_H
#define FORGETFULSTACK_H

#include <memory>
#include <vector>
#include <iostream>

#define min(x, y) (x) < (y) ? (x) : (y)

template <typename T> class ForgetfulStack
{
    std::vector<T> buffer;
    std::size_t    head     = 0;
    std::size_t    max_size = 0;
    std::size_t    n_el     = 0;

    T empty_el;

  public:
    ForgetfulStack(std::size_t size, T empty_el)
        : buffer(size), max_size(size), empty_el(empty_el)
    {
    }

    void push(const T value)
    {
        buffer[head] = value;
        head         = (head + 1) % max_size;
        n_el         = min(n_el + 1, max_size);
    }

    T pop()
    {
        if (n_el <= 0)
            return empty_el;
        n_el--;
        head = (head - 1 + max_size) % max_size;
        return buffer[head];
    }

    T top()
    {
        if (n_el <= 0)
            return empty_el;
        return buffer[(head - 1 + max_size) % max_size];
    }

    std::size_t size() { return min(n_el, max_size) + 1; }
};

#endif