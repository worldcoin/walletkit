import test from "ava";

import { Hello } from "../index.js";

test("hello", (t) => {
  const hello = new Hello();
  const testAsync = async () => {
    const out = await hello.echo("hello");
    t.is(out, "hello");
  };
  const out = hello.sayHello();
  t.is(out, "Hello, World!");
});
