'use strict';
//
// File: instance_slot.ts
//
// ---------------------------------------------------------------------------
// ONE MODULE'S INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2, 2026-09-16).
//
// rcbj's decision for R2 (issue #50): `common/protocol_stack.ts` builds every
// converted class once and passes the instances through constructors; no
// module builds its own. What stays in each module is a set of FACADES — its
// old export names, forwarding to the instance the root built — because the
// JavaScript still here (the files the parent project copies, and the tests)
// calls converted modules through `require(...)` and cannot be handed an
// instance. A facade is deleted when its last JavaScript caller is converted.
//
// An `InstanceSlot` is the one place a module's instance lives:
//
//   * `install(instance)` — the ROOT puts the instance it built here. It runs
//     the module's `wire` step (the slot fills, tables and other work the
//     module used to do at load with its own instance) and records the origin
//     as `root`. Installing twice, or after a default was built, is refused:
//     two instances of one module would split the state their fields hold,
//     and the second would leave the first's wiring pointing at the wrong one.
//   * `get()` — what every facade calls. When nothing is installed — a process
//     that loads one module without the root, which is every in-process test
//     that does — it builds the DEFAULT instance from the module's
//     `defaultDeps()`, wires it, and records the origin as `default`.
//   * `origin()` — which of the two happened, or `none`. The root checks this
//     for every slot after it has loaded the stack, and a service in which any
//     module built its own instance does not start (see `protocol_stack.ts`).
//     That check is what makes "no module builds its own instance" a property
//     of the running service rather than a hope.
//   * `forward(name)` — a facade function: the same call, on whichever
//     instance `get()` answers. Written once here so the facades in every
//     module are one line each.
//   * `buildNowUnlessDeferred()` — the last statement of every module on
//     this pattern. A process that loads a module WITHOUT the root (an
//     in-process test, a tool) gets the default instance built and wired at
//     that point, which is exactly what loading the module did before R2 —
//     slot fills and all. Once the root has called `deferToRoot()`, it does
//     nothing: the root installs the instance itself.
//
// **`deferToRoot()` IS A PROCESS-WIDE FLAG, AND ON PURPOSE.** It is not an
// instance of anything: it records that a composition root is loading this
// process, which is a fact about the process. It lives here, on the one
// class every module on the pattern already requires, so that no module has
// to ask the root (which would be a cycle) whether one is running.
//
// A LIBRARY (rule 3): it requires nothing of this service, so any module can
// require it without joining a cycle, and its logger is handed in.
// ---------------------------------------------------------------------------

type Origin = 'none' | 'root' | 'default';

interface SlotLog {
  debug(message: string): void;
}

class InstanceSlot<T extends object> {
  private static deferred = false;
  private instance: T | null = null;
  private how: Origin = 'none';

  // The composition root calls this before it loads anything.
  static deferToRoot(): void {
    InstanceSlot.deferred = true;
  }

  // `name` is the module's path, for messages; `build` makes the default
  // instance; `wire` is the module's own work with an instance, run once for
  // whichever instance is installed.
  constructor(private readonly name: string,
              private readonly build: () => T,
              private readonly wire: ((instance: T) => void) | null,
              private readonly log: SlotLog) {
    log.debug("Entering InstanceSlot.constructor(). " + name);
    log.debug("Leaving InstanceSlot.constructor().");
  }

  install(instance: T): void {
    this.log.debug("Entering InstanceSlot.install(). " + this.name);
    if (this.instance) {
      this.log.debug("Leaving InstanceSlot.install(). Already " + this.how +
                     ".");
      throw new Error(this.name + ': an instance is already installed (' +
                      this.how + '), so the composition root cannot install ' +
                      'another. Two instances of one module would split its ' +
                      'state; the root must install before anything uses it.');
    }
    this.instance = instance;
    this.how = 'root';
    if (this.wire) {
      this.wire(instance);
    }
    this.log.debug("Leaving InstanceSlot.install().");
  }

  // Called on every facade call, so no Entering/Leaving pair — the hot-path
  // exception the code style allows, stated here as it requires.
  get(): T {
    if (this.instance) {
      return this.instance;
    }
    const built = this.build();
    this.instance = built;
    this.how = 'default';
    if (this.wire) {
      this.wire(built);
    }
    return built;
  }

  buildNowUnlessDeferred(): void {
    this.log.debug("Entering InstanceSlot.buildNowUnlessDeferred(). " +
                   this.name);
    if (!InstanceSlot.deferred) {
      this.get();
    }
    this.log.debug("Leaving InstanceSlot.buildNowUnlessDeferred(). " +
                   this.how);
  }

  origin(): Origin {
    this.log.debug("Entering InstanceSlot.origin(). " + this.name);
    this.log.debug("Leaving InstanceSlot.origin(). " + this.how);
    return this.how;
  }

  // A facade for one method: callable before anything is installed, and
  // resolving the instance at call time. Built once per export at load.
  forward<K extends keyof T>(key: K): T[K] {
    this.log.debug("Entering InstanceSlot.forward(). " + this.name + '.' +
                   String(key));
    const slot = this;
    // Runs on every facade call, so no Entering/Leaving pair — the hot-path
    // exception the code style allows, stated here as it requires.
    const facade = function (...args: unknown[]): unknown {
      const target = slot.get();
      const method = target[key] as unknown as
        (...inner: unknown[]) => unknown;
      return method.apply(target, args);
    };
    this.log.debug("Leaving InstanceSlot.forward().");
    return facade as unknown as T[K];
  }
}

export = InstanceSlot;
