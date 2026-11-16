import {
  parseImpressionMarkdown,
  plainImpressionText,
} from "./impressionMarkdownParser.js";

const DEFAULT_COLOR = "#334155";
const DEFAULT_SIZE = 10;

const COLORS = {
  heading: "#172033",
  body: "#334155",
  muted: "#64748b",
  warning: "#9a3412",
  success: "#166534",
  isotope: "#4338ca",
  divider: "#e2e8f0",
};

const FONT = {
  body: 10,
  small: 9,
  title: 15,
  impressionHeading: 11,
  markdownHeading: {
    1: 16,
    2: 14,
    3: 12,
    4: 11,
    5: 10,
    6: 10,
  },
};

function fontName(style = {}) {
  if (style.bold && style.italic) return "Helvetica-BoldOblique";
  if (style.bold) return "Helvetica-Bold";
  if (style.italic) return "Helvetica-Oblique";
  return "Helvetica";
}

function mergeStyle(parent, child) {
  return { ...parent, ...child };
}

/**
 * Convert parsed Markdown nodes into plain inline text runs.
 * Admin-specific colours and font sizes are intentionally ignored.
 */
function collectRuns(nodes = [], style = {}, output = []) {
  for (const node of nodes) {
    if (node.type === "text") {
      output.push({
        text: node.value,
        style,
      });
      continue;
    }

    if (node.type === "break" || node.type === "softbreak") {
      output.push({ text: " ", style });
      continue;
    }

    if (node.type === "styledSpan") {
      const inlineStyle = node.data?.hProperties?.style || "";

      // Preserve emphasis from highlighted content, but ignore
      // admin-configured colours and font sizes.
      const isHighlight = inlineStyle.includes("background-color");

      collectRuns(
        node.children,
        mergeStyle(style, isHighlight ? { bold: true } : {}),
        output,
      );
      continue;
    }

    if (node.type === "strong") {
      collectRuns(node.children, mergeStyle(style, { bold: true }), output);
      continue;
    }

    if (node.type === "emphasis") {
      collectRuns(node.children, mergeStyle(style, { italic: true }), output);
      continue;
    }

    if (node.type === "delete") {
      collectRuns(node.children, mergeStyle(style, { strike: true }), output);
      continue;
    }

    if (node.type === "link" || node.type === "linkReference") {
      collectRuns(
        node.children,
        mergeStyle(style, { underline: true }),
        output,
      );
      continue;
    }

    if (node.type === "inlineCode") {
      output.push({
        text: node.value,
        style: mergeStyle(style, { bold: true }),
      });
      continue;
    }

    if (Array.isArray(node.children)) {
      collectRuns(node.children, style, output);
    }
  }

  return output;
}

/**
 * Apply consistent PDF styles to meaningful content.
 * This does not depend on admin-selected font sizes or colours.
 */
function applySemanticFormatting(runs) {
  const result = [];

  // Common isotope notation: Ir-192, Co-60, Cs-137, Am-241.
  const semanticPattern =
    /(Important:|RSO Declaration:|\b[A-Z][a-z]?-\d{1,3}(?:m\d?)?\b)/g;

  for (const run of runs) {
    const text = run.text || "";
    let lastIndex = 0;

    for (const match of text.matchAll(semanticPattern)) {
      const index = match.index ?? 0;
      const matchedText = match[0];

      if (index > lastIndex) {
        result.push({
          text: text.slice(lastIndex, index),
          style: run.style,
        });
      }

      let semanticStyle = {};

      if (matchedText === "Important:") {
        semanticStyle = {
          bold: true,
          color: COLORS.warning,
        };
      } else if (matchedText === "RSO Declaration:") {
        semanticStyle = {
          bold: true,
          color: COLORS.success,
        };
      } else {
        semanticStyle = {
          bold: true,
          color: COLORS.isotope,
        };
      }

      result.push({
        text: matchedText,
        style: mergeStyle(run.style || {}, semanticStyle),
      });

      lastIndex = index + matchedText.length;
    }

    if (lastIndex < text.length) {
      result.push({
        text: text.slice(lastIndex),
        style: run.style,
      });
    }
  }

  return result;
}

/**
 * Render inline runs using PDFKit's continued-text support.
 * Font sizes here are PDF points, not CSS pixels.
 */
function renderRuns(doc, nodes, baseStyle = {}) {
  const collected = collectRuns(nodes, baseStyle);
  const runs = applySemanticFormatting(collected);

  if (!runs.length) {
    doc.text("");
    return;
  }

  runs.forEach((run, index) => {
    const style = run.style || {};
    const isLast = index === runs.length - 1;

    doc
      .font(fontName(style))
      .fontSize(baseStyle.size || FONT.body)
      .fillColor(style.color || baseStyle.color || COLORS.body)
      .text(run.text, {
        continued: !isLast,
        underline: Boolean(style.underline),
        lineGap: 2,
      });
  });
}

function splitImportantParagraph(node) {
  const runs = collectRuns(node.children || []);
  const blocks = [];
  let current = [];

  for (const run of runs) {
    const parts = run.text.split(/(Important:)/i);

    for (const part of parts) {
      if (!part) continue;

      if (/^Important:$/i.test(part)) {
        if (current.length) {
          blocks.push({ type: "normal", runs: current });
          current = [];
        }

        current.push({
          text: part,
          style: {
            ...run.style,
            bold: true,
            color: "#92400e",
          },
        });

        blocks.push({ type: "important", runs: current });
        current = [];
      } else {
        current.push({ ...run, text: part });
      }
    }
  }

  if (current.length) {
    blocks.push({ type: "normal", runs: current });
  }

  return blocks;
}

function ensureSpace(doc, requiredHeight = 35) {
  const bottomLimit = doc.page.height - doc.page.margins.bottom;

  if (doc.y + requiredHeight > bottomLimit) {
    doc.addPage();
  }
}

function renderParagraph(doc, node, options = {}) {
  const blocks = splitImportantParagraph(node);

  for (const block of blocks) {
    if (!block.runs.length) continue;

    if (block.type === "important") {
      doc.moveDown(0.3);
    }

    block.runs.forEach((run, index) => {
      const style = run.style || {};

      doc
        .font(fontName(style))
        .fontSize(10)
        .fillColor(style.color || DEFAULT_COLOR)
        .text(run.text, {
          continued: index !== block.runs.length - 1,
        });
    });

    doc.moveDown(block.type === "important" ? 0.3 : 0.2);
  }
}

function getPlainNodeText(node) {
  if (!node) return "";

  if (node.type === "text" || node.type === "inlineCode") {
    return node.value || "";
  }

  if (!Array.isArray(node.children)) {
    return "";
  }

  return node.children.map(getPlainNodeText).join("");
}

function renderList(doc, node, depth = 0) {
  const items = node.children || [];
  const ordered = Boolean(node.ordered);
  const indent = depth * 14;

  items.forEach((item, index) => {
    const marker = ordered ? `${index + 1}.` : "•";
    const paragraphs = (item.children || []).filter(
      (child) => child.type === "paragraph",
    );

    const nestedLists = (item.children || []).filter(
      (child) => child.type === "list",
    );

    const otherBlocks = (item.children || []).filter(
      (child) => child.type !== "paragraph" && child.type !== "list",
    );

    const firstParagraph = paragraphs.shift();

    doc
      .font("Helvetica")
      .fontSize(FONT.body)
      .fillColor(COLORS.body)
      .text(marker, {
        continued: Boolean(firstParagraph),
        indent,
        hanging: 4,
      });

    if (firstParagraph) {
      renderRuns(doc, firstParagraph.children || [], {
        color: COLORS.body,
        size: FONT.body,
      });

      doc.moveDown(0.2);
    }

    for (const paragraph of paragraphs) {
      doc.x = doc.page.margins.left + indent + 14;

      renderRuns(doc, paragraph.children || [], {
        color: COLORS.body,
        size: FONT.body,
      });

      doc.moveDown(0.2);
    }

    for (const child of otherBlocks) {
      renderBlock(doc, child, { depth: depth + 1 });
    }

    for (const nestedList of nestedLists) {
      renderList(doc, nestedList, depth + 1);
    }
  });

  doc.moveDown(0.2);
}

function renderBlock(doc, node, options = {}) {
  switch (node.type) {
    case "paragraph":
      renderParagraph(doc, node);
      break;

    case "heading": {
      const headingSize = FONT.markdownHeading[node.depth] || 11;

      ensureSpace(doc, headingSize + 12);

      doc.moveDown(0.25);

      renderParagraph(doc, node, {
        size: headingSize,
        bold: true,
        color: COLORS.heading,
        spacing: 0.3,
      });
      break;
    }

    case "list":
      renderList(doc, node, options.depth || 0);
      break;

    case "blockquote":
      doc.save().fillColor(COLORS.muted);

      for (const child of node.children || []) {
        renderBlock(doc, child, options);
      }

      doc.restore();
      break;

    case "code":
      doc
        .font("Courier")
        .fontSize(FONT.small)
        .fillColor(COLORS.muted)
        .text(node.value || "", {
          indent: 12,
          lineGap: 2,
        });

      doc.moveDown(0.4);
      break;

    case "thematicBreak":
      doc.moveDown(0.3);

      doc
        .moveTo(doc.page.margins.left, doc.y)
        .lineTo(doc.page.width - doc.page.margins.right, doc.y)
        .strokeColor(COLORS.divider)
        .stroke();

      doc.moveDown(0.5);
      break;

    case "table":
      for (const row of node.children || []) {
        const cells = (row.children || []).map((cell) =>
          getPlainNodeText(cell).trim(),
        );

        doc
          .font("Helvetica")
          .fontSize(FONT.small)
          .fillColor(COLORS.body)
          .text(cells.join("     |     "), {
            lineGap: 2,
          });
      }

      doc.moveDown(0.4);
      break;

    default:
      if (Array.isArray(node.children)) {
        for (const child of node.children) {
          renderBlock(doc, child, options);
        }
      }
  }
}

function renderImpressionTitle(doc, title, index) {
  const cleanTitle = plainImpressionText(title || "Untitled") || "Untitled";

  ensureSpace(doc, 40);

  doc
    .font("Helvetica-Bold")
    .fontSize(FONT.impressionHeading)
    .fillColor(COLORS.heading)
    .text(`${index + 1}. ${cleanTitle}`, {
      lineGap: 2,
    });

  doc.moveDown(0.2);
}

export function renderImpressionSummary(doc, impressions) {
  const entries = Array.isArray(impressions)
    ? impressions
    : impressions
      ? [impressions]
      : [];

  if (!entries.length) {
    doc
      .font("Helvetica")
      .fontSize(FONT.body)
      .fillColor(COLORS.body)
      .text("No impression available.");

    doc.moveDown(0.5);
    return;
  }

  entries.forEach((item, index) => {
    renderImpressionTitle(doc, item.title, index);

    const description = item.description || "";
    const tree = parseImpressionMarkdown(description);

    for (const node of tree.children || []) {
      renderBlock(doc, node);
    }

    doc.moveDown(0.45);
  });
}
