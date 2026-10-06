import test from "node:test";
import assert from "node:assert/strict";
import {readResponse, ResponseLimitError} from "../index.mjs";

function body(parts, failure) {
  let consumed = 0, closed = 0, destroyed = 0;
  return {get consumed() {return consumed;}, get closed() {return closed;}, get destroyed() {return destroyed;},
    destroy() {destroyed++;}, async *[Symbol.asyncIterator]() {
      try {for (const part of parts) {consumed++; yield part;} if (failure) throw failure;}
      finally {closed++;}
    }};
}
test("complete short binary chunks and exact empty response close the body", async () => {
  const b = body([Buffer.from("a"), new Uint8Array([0, 255]), Buffer.alloc(0)]);
  assert.deepEqual(await readResponse(b, {maximum: 3}), Buffer.from([97, 0, 255]));
  assert.equal(b.destroyed, 1); assert.equal(b.closed, 1);
  const empty = body([]); assert.equal((await readResponse(empty, {maximum: 0})).length, 0);
  assert.equal(empty.destroyed, 1);
});
test("overflow stops before later chunks and preserves the app's exact error", async () => {
  const b = body([Buffer.from("abc"), Buffer.from("d"), Buffer.from("private later data")]);
  const error = Object.assign(new Error("App limit"), {status: 409});
  await assert.rejects(readResponse(b, {maximum: 3, limitError: () => error}), e => e === error);
  assert.equal(b.consumed, 2); assert.equal(b.closed, 1); assert.equal(b.destroyed, 1);
  await assert.rejects(readResponse(body([Buffer.from("x")]), {maximum: 0}), ResponseLimitError);
});
test("invalid limits and nonbinary chunks fail while closing the response", async () => {
  for (const maximum of [undefined, -1, Infinity, NaN, 1.5, Number.MAX_SAFE_INTEGER + 1, "3"]) {
    const b = body([]); await assert.rejects(readResponse(b, {maximum}), TypeError);
    assert.equal(b.destroyed, 1); assert.equal(b.consumed, 0);
  }
  for (const part of ["é", {}, [1, 2]]) {
    const b = body([part]); await assert.rejects(readResponse(b, {maximum: 3}), TypeError);
    assert.equal(b.destroyed, 1); assert.equal(b.closed, 1);
  }
});
test("transport failure is preserved and destroy errors retain finally precedence", async () => {
  const error = new Error("Interrupted transport"), b = body([Buffer.from("a")], error);
  await assert.rejects(readResponse(b, {maximum: 3}), e => e === error); assert.equal(b.destroyed, 1);
  const close = new Error("Close failed"), c = body([], error); c.destroy = () => {throw close;};
  await assert.rejects(readResponse(c, {maximum: 3}), e => e === close);
});
test("retained chunks cannot be changed by a provider reusing its buffer", async () => {
  const part = Buffer.from("ab");
  const b = {async *[Symbol.asyncIterator]() {yield part; part.fill(120); yield Buffer.from("c");}};
  assert.equal((await readResponse(b, {maximum: 3})).toString(), "abc");
});
