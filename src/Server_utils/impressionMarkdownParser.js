import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";

const colors = {
  red: "#b91c1c",
  amber: "#92400e",
  blue: "#1d4ed8",
  green: "#15803d",
  purple: "#7e22ce",
};

const sizes = new Set([12, 14, 16, 18, 20, 24]);
const tokenPattern = /(==|\[\/?(?:color|size)(?::[^\]\n]+)?\])/g;

function getStyle(marker) {
  if (marker.type === "highlight") {
    return [
      "background-color:#fef08a",
      "color:#713f12",
      "font-weight:700",
      "border-radius:2px",
    ].join(";");
  }

  if (marker.type === "color") {
    return `color:${colors[marker.value]}`;
  }

  return `font-size:${Number(marker.value)}px`;
}

function getOpeningMarker(token) {
  if (token === "==") {
    return { type: "highlight" };
  }

  const color = token.match(/^\[color:([a-z]+)\]$/);

  if (color && colors[color[1]]) {
    return { type: "color", value: color[1] };
  }

  const size = token.match(/^\[size:(\d+)\]$/);

  if (size && sizes.has(Number(size[1]))) {
    return { type: "size", value: size[1] };
  }

  return null;
}

function parseStyledText(value) {
  const root = [];

  const stack = [{ marker: null, children: root }];
  let last = 0;

  function appendText(text) {
    if (!text) return;

    stack[stack.length - 1].children.push({
      type: "text",
      value: text,
    });
  }

  for (const match of value.matchAll(tokenPattern)) {
    const index = match.index ?? 0;
    const token = match[0];

    appendText(value.slice(last, index));

    const current = stack[stack.length - 1].marker;

    const closingType =
      token === "==" && current?.type === "highlight"
        ? "highlight"
        : token === "[/color]"
          ? "color"
          : token === "[/size]"
            ? "size"
            : null;

    if (closingType && current?.type === closingType && stack.length > 1) {
      stack.pop();
    } else {
      const opening = getOpeningMarker(token);

      if (opening) {
        const node = {
          type: "styledSpan",
          children: [],
          data: {
            hName: "span",
            hProperties: {
              style: getStyle(opening),
            },
          },
        };

        stack[stack.length - 1].children.push(node);

        stack.push({
          marker: opening,
          children: node.children,
        });
      } else {
        appendText(token);
      }
    }

    last = index + token.length;
  }

  appendText(value.slice(last));

  return root;
}

const remarkImpressionStyles = () => (tree) => {
  function transform(node) {
    if (!node || !Array.isArray(node.children)) return;

    const children = node.children;

    for (let i = 0; i < children.length; i++) {
      const child = children[i];

      if (child.type === "text" && tokenPattern.test(child.value)) {
        tokenPattern.lastIndex = 0;

        const parts = parseStyledText(child.value);

        children.splice(i, 1, ...parts);
        i += parts.length - 1;
      } else {
        transform(child);
      }

      tokenPattern.lastIndex = 0;
    }
  }

  transform(tree);
};

export function normalizeImpression(value = "") {
  return String(value)
    .replace(/<\/?text\b[^>]*>/gi, "")
    .trim();
}

export function parseImpressionMarkdown(value = "") {
  const processor = unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(remarkImpressionStyles);

  const tree = processor.parse(normalizeImpression(value));

  return processor.runSync(tree);
}

export function plainImpressionText(value = "") {
  return normalizeImpression(value)
    .replace(/\[\/?(?:color|size)(?::[^\]\n]+)?\]/g, "")
    .replace(/==/g, "")
    .replace(/!\[([^\]]*)\]\([^)]+\)/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/(\*\*|__|~~)/g, "")
    .replace(/[`*_]/g, "")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/^\s*(?:[-*+]|\d+\.)\s+/gm, "")
    .replace(/\s+/g, " ")
    .trim();
}
