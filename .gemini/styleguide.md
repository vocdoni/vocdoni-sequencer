# Vocdoni Go Style Guide

This document outlines the coding conventions for Go code in Vocdoni’s repositories. It is based on the principles of [Effective Go](https://golang.org/doc/effective_go) and incorporates both our team’s specific guidelines and additional idiomatic practices to ensure clarity, maintainability, consistency, and performance.

---

## Key Principles

- **Readability:** Code should be self-explanatory and easy to follow.
- **Maintainability:** Changes and extensions should be straightforward and error-free.
- **Consistency:** A uniform style across all projects reduces mistakes and speeds up collaboration.
- **Performance:** Write efficient code without compromising clarity.

---

## Idiomatic Go Practices

### Error Handling
- **Always check errors:** Every error returned must be checked. Never ignore an error.
- **Inline error checking:** Use inline error checking to keep error handling close to the source.
  
  ```go
  if err := doSomething(); err != nil {
      return fmt.Errorf("failed to do something: %w", err)
  }
  ```
- **Error message construction:** Use `fmt.Errorf()` with `%w` for wrapping errors, making them chainable and easier to inspect later.
- **Use errors.Is / errors.As:** When handling errors, leverage the standard library’s error inspection functions.

### Logging
- **Key/Value Logging:** Use logging functions with key/value pairs (e.g., `log.Debugw`, `log.Infow`) to provide structured context.
  
  ```go
  log.Debugw("starting process", "processID", processID)
  ```
- **Message style:** Log and error messages must start with a non-capital letter.
  
  ```go
  log.Infow("starting api server", "host", conf.Host, "port", conf.Port)
  ```

### Code Formatting
- **Use gofumpt:** Format your code with [gofumpt](https://github.com/mvdan/gofumpt) for a consistent, strict style that builds upon gofmt.

### Function and Method Signatures
- **Manage multiple parameters/returns:** If a function or method has more than three parameters or return values, pack them into a struct to improve readability.
  
  ```go
  type ComplexInput struct {
      A int
      B string
      C bool
      D float64
  }
  
  type ComplexOutput struct {
      Result string
      Err    error
  }
  
  func complexFunc(input ComplexInput) ComplexOutput { ... }
  ```

### Documentation
- **Exported entities:** All exported methods, functions, and types **MUST** be documented. Follow [godoc](https://blog.golang.org/godoc) conventions by writing a brief summary that starts with the entity’s name.
  
  ```go
  // APIConfig represents the configuration for the API HTTP server.
  type APIConfig struct {
      Host    string
      Port    int
      Storage *Storage // Optional: use an existing storage instance.
  }
  ```

### Variable Declaration and Usage
- **Locality of variables:** Declare variables as close as possible to their point of use.
- **Avoid variable reuse:** Do not reuse variables to improve clarity; declare new variables as needed.
- **Prefer short variable names:** For short-lived variables in small scopes, concise names are acceptable, but be mindful of clarity.

### Complex Types
- **Pointers for complex types:** When passing or returning complex or large data structures, use pointers to minimize copying and clarify mutability.
- **Immutable vs. mutable:** When data should not be modified, consider passing values instead of pointers.

### Concurrency and Context
- **Safe parallelization:** Use concurrency patterns (goroutines, channels, mutexes) only when there is a clear benefit. Always ensure that shared state is safe from data races.
- **Use context:** Functions that perform I/O or long-running operations should accept a `context.Context` to support cancellation and timeouts.
  
  ```go
  func fetchData(ctx context.Context, url string) ([]byte, error) {
      // ...
  }
  ```
- **Defer for cleanup:** Always use `defer` to ensure that resources (files, connections, locks) are released even if an error occurs.
  
  ```go
  file, err := os.Open("data.txt")
  if err != nil {
      return err
  }
  defer file.Close()
  ```

### Interface Design
- **Small and focused interfaces:** Define interfaces in the consumer package and keep them minimal, typically with one or two methods.
- **Interface satisfaction:** Let types implicitly satisfy interfaces. Declare interfaces only when they add value to your design.
  
  ```go
  type Reader interface {
      Read(p []byte) (n int, err error)
  }
  ```
- **Avoid overgeneralization:** Do not create interfaces for every type; only abstract when multiple implementations are expected.

### Resource Management
- **Defer closing:** Always check errors when deferring resource cleanup if the error is significant to the function logic.
- **Limit global state:** Avoid global variables whenever possible to reduce hidden dependencies and improve testability.

### Code Organization and Project Structure
- **Package structure:** Organize code into packages that group related functionality. Package names should be short, lowercase, and avoid stuttering (e.g., prefer `storage` over `vocdoniStorage`).
- **Separation of concerns:** Each package should have a clear responsibility. Keep business logic, infrastructure, and utility functions well separated.
- **Avoid cyclic dependencies:** Design your package dependencies to be acyclic for better modularity and maintainability.

### Testing Best Practices
- **Test early and often:** Write tests for all new features and bug fixes. Use table-driven tests for similar test cases.
  
  ```go
  func TestAdd(t *testing.T) {
      tests := []struct {
          a, b int
          want int
      }{
          {1, 2, 3},
          {2, 3, 5},
      }
      for _, tt := range tests {
          if got := Add(tt.a, tt.b); got != tt.want {
              t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
          }
      }
  }
  ```
- **Unit vs. integration tests:** When unit tests are not feasible, write integration tests to cover broader system interactions.
- **Race detection:** Use the race detector (`go test -race`) to catch data races in concurrent code.
- **Mock dependencies:** Where appropriate, use interfaces and dependency injection to enable easier testing of isolated units.

### Performance and Optimization
- **Avoid premature optimization:** Write clear, correct code first. Optimize only after profiling and identifying actual bottlenecks.
- **Benchmark critical paths:** Use Go’s benchmarking tools to measure performance where needed.
- **Efficient use of slices and maps:** Preallocate slices when possible and avoid unnecessary copying of large data structures.

### General Best Practices
- **Simplicity over cleverness:** Write code that is simple and clear rather than overly clever. Readability is more important than saving a few lines of code.
- **Follow standard library practices:** When in doubt, look at the standard library for inspiration on how to structure your code.
- **Avoid unnecessary abstractions:** Introduce abstraction only when it improves clarity or reuse, not simply to over-engineer the solution.

