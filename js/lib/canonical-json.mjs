function assertScalar(value) {
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("canonical JSON does not support non-finite numbers");
  }
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw new TypeError("unpaired high surrogate");
        }
        index += 1;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw new TypeError("unpaired low surrogate");
      }
    }
  }
}

export function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    assertScalar(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value !== "object") {
    throw new TypeError(`unsupported JSON value: ${typeof value}`);
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${canonicalize(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

// JSON.parse accepts duplicate members. Conformance input must not silently
// collapse them, so this deliberately small parser rejects them at every depth.
export function parseJson(text) {
  let offset = 0;
  const fail = (message) => { throw new SyntaxError(`${message} at byte ${Buffer.byteLength(text.slice(0, offset), "utf8")}`); };
  const whitespace = () => { while (/\s/u.test(text[offset] ?? "")) offset += 1; };
  const string = () => {
    const start = offset;
    if (text[offset++] !== '"') fail("expected string");
    let escaped = false;
    while (offset < text.length) {
      const char = text[offset++];
      if (!escaped && char === '"') {
        const value = JSON.parse(text.slice(start, offset));
        assertScalar(value);
        return value;
      }
      if (!escaped && char.charCodeAt(0) < 0x20) fail("control character in string");
      if (!escaped && char === "\\") escaped = true;
      else escaped = false;
    }
    fail("unterminated string");
  };
  const value = () => {
    whitespace();
    const char = text[offset];
    if (char === '"') return string();
    if (char === "{") {
      offset += 1; whitespace();
      const result = {}; const seen = new Set();
      if (text[offset] === "}") { offset += 1; return result; }
      while (true) {
        whitespace(); const key = string();
        if (seen.has(key)) fail(`duplicate member ${JSON.stringify(key)}`);
        seen.add(key); whitespace();
        if (text[offset++] !== ":") fail("expected colon");
        result[key] = value(); whitespace();
        const delimiter = text[offset++];
        if (delimiter === "}") return result;
        if (delimiter !== ",") fail("expected comma or closing brace");
      }
    }
    if (char === "[") {
      offset += 1; whitespace(); const result = [];
      if (text[offset] === "]") { offset += 1; return result; }
      while (true) {
        result.push(value()); whitespace();
        const delimiter = text[offset++];
        if (delimiter === "]") return result;
        if (delimiter !== ",") fail("expected comma or closing bracket");
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(text.slice(offset));
    if (!match) fail("invalid JSON value");
    offset += match[0].length;
    return JSON.parse(match[0]);
  };
  if (text.charCodeAt(0) === 0xfeff) fail("BOM is forbidden");
  const result = value(); whitespace();
  if (offset !== text.length) fail("trailing content");
  return result;
}
