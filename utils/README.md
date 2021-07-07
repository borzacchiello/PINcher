# Utils

Utility scripts

#### filter_callgraph

```
usage: filter_callgraph [-h] [--highlight-lib [LIB ...]] [--filter-out-lib [LIB ...]] [--connected-with [NODE]] [--demangle-cpp] [--radius [R]] callgraph

Filter callgraph utility

positional arguments:
  callgraph             The callgraph in dot format

optional arguments:
  -h, --help            show this help message and exit
  --highlight-lib [LIB ...]
                        Highlight nodes of lib
  --filter-out-lib [LIB ...]
                        Filter out functions of lib
  --connected-with [NODE]
                        Keep nodes connected with this node (label)
  --demangle-cpp        Demangle C++ labels (c++filt command must be in path)
  --radius [R]          Specify maximum connected radius R (discard nodes whose distance from connected node is greater than R). If omitted, R = inf
```

ex: `./filter_callgraph --connected-with node --filter-out-lib "libc.so" --highlight-lib "libfoo.so" --radius 1 /dev/shm/callgraph.dot | xdot -`
