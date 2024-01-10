// To build this file:
// - Navigate to the project root where package.json is located.
// - Run npm install
// - Run ./node_modules/.bin/esbuild ./static/codemirror.ts --outfile=./static/codemirror.js --bundle --minify
import { EditorState, Prec, Compartment } from '@codemirror/state';
import { EditorView, lineNumbers, keymap } from '@codemirror/view';
import { indentWithTab, history, defaultKeymap, historyKeymap } from '@codemirror/commands';
import { indentOnInput, indentUnit, syntaxHighlighting, defaultHighlightStyle } from '@codemirror/language';
import { autocompletion, completionKeymap } from '@codemirror/autocomplete';
import { html } from "@codemirror/lang-html";
import { css } from "@codemirror/lang-css";
import { javascript } from "@codemirror/lang-javascript";
import { markdown, markdownLanguage } from "@codemirror/lang-markdown";
// import { languages } from '@codemirror/language-data';

for (const [index, dataCodemirror] of document.querySelectorAll<HTMLElement>("[data-codemirror]").entries()) {
  // The textarea we are overriding.
  const textarea = dataCodemirror.querySelector("textarea");
  if (!textarea) {
    continue;
  }

  // Locate the parent form that houses the textarea.
  let form: HTMLFormElement | undefined;
  let element = textarea.parentElement;
  while (element != null) {
    if (element instanceof HTMLFormElement) {
      form = element;
      break;
    }
    element = element.parentElement;
  }
  if (!form) {
    continue;
  }

  // Create the codemirror editor.
  const language = new Compartment();
  const wordwrap = new Compartment();
  const editorView = new EditorView({
    state: EditorState.create({
      doc: textarea.value,
      extensions: [
        // Basic extensions copied from basicSetup in
        // https://github.com/codemirror/basic-setup/blob/main/src/codemirror.ts.
        lineNumbers(),
        history(),
        indentUnit.of("  "),
        indentOnInput(),
        autocompletion(),
        keymap.of([
          indentWithTab,
          ...defaultKeymap,
          ...historyKeymap,
          ...completionKeymap,
        ]),
        syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
        // Dynamic settings.
        language.of([]),
        wordwrap.of([]),
        // Custom theme.
        EditorView.theme({
          "&": {
            fontSize: "11.5pt",
            border: "1px solid black",
            backgroundColor: "white",
          },
          ".cm-content": {
            fontFamily: "Menlo, Monaco, Lucida Console, monospace",
            minHeight: "16rem"
          },
          ".cm-scroller": {
            overflow: "auto",
          }
        }),
        // Custom keymaps.
        Prec.high(keymap.of([
          {
            // Ctrl-s/Cmd-s to save.
            key: "Mod-s",
            run: function(_: EditorView): boolean {
              if (form) {
                // Trigger all submit events on the form, so that the
                // codemirror instances have a chance to sychronize
                // with the textarea instances.
                form.dispatchEvent(new Event("submit"));
                // Actually submit the form.
                form.submit();
              }
              return true;
            },
          },
        ])),
      ],
    }),
  });

  // Replace the textarea with the codemirror editor.
  textarea.style.display = "none";
  textarea.after(editorView.dom);

  // Restore cursor position from localStorage.
  const position = Number(localStorage.getItem(`${window.location.pathname}:${index}`));
  if (position && position <= textarea.value.length) {
    editorView.dispatch({
      selection: { anchor: position, head: position },
    });
  }

  // If the textarea has autofocus on, shift focus to the codemirror editor.
  if (textarea.hasAttribute("autofocus")) {
    const cmContent = editorView.dom.querySelector<HTMLElement>(".cm-content");
    if (cmContent) {
      cmContent.focus();
    }
  }

  // On submit, synchronize the codemirror editor's contents with the
  // textarea it is paired with (before the form is submitted).
  form.addEventListener("submit", function() {
    // Save the cursor position to localStorage.
    const ranges = editorView.state.selection.ranges;
    if (ranges.length > 0) {
      const position = ranges[0].from;
      localStorage.setItem(`${window.location.pathname}:${index}`, position.toString());
    }
    // Copy the codemirror editor's contents to the textarea.
    textarea.value = editorView.state.doc.toString();
  });

  // Configure language.
  const ext = dataCodemirror.getAttribute("data-codemirror")?.trim();
  if (ext == ".html") {
    editorView.dispatch({
      effects: language.reconfigure(html()),
    });
  } else if (ext == ".css") {
    editorView.dispatch({
      effects: language.reconfigure(css()),
    });
  } else if (ext == ".js") {
    editorView.dispatch({
      effects: language.reconfigure(javascript()),
    });
  } else if (ext == ".md") {
    editorView.dispatch({
      effects: language.reconfigure(markdown({
        base: markdownLanguage,
        // codeLanguages: languages,
      })),
    });
  }

  // Configure word wrap.
  if (ext) {
    let checked = false;
    if (localStorage.getItem(`wordwrap:${ext}`) == "true") {
      checked = true;
    } else {
      checked = ext != ".html" && ext != ".css" && ext != ".js";
    }
    if (checked) {
      wordwrap.reconfigure(EditorView.lineWrapping);
    }
    const wordwrapInput = document.querySelector<HTMLInputElement>(`input[type=checkbox]#wordwrap\\:${index}`);
    if (wordwrapInput) {
      wordwrapInput.checked = checked;
      wordwrapInput.addEventListener("change", function() {
        if (wordwrapInput.checked) {
          localStorage.setItem(`wordwrap:${ext}`, "true");
          editorView.dispatch({
            effects: wordwrap.reconfigure(EditorView.lineWrapping),
          });
        } else {
          localStorage.setItem(`wordwrap:${ext}`, "false");
          editorView.dispatch({
            effects: wordwrap.reconfigure([]),
          });
        }
      });
    }
  }
}
