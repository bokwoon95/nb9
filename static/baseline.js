document.body.parentElement.addEventListener("click", (event) => {
  let activeDetails = null;
  let element = event.target;
  while (element != null) {
    if (element.tagName != "DETAILS") {
      element = element.parentElement;
      continue;
    }
    activeDetails = element;
    break;
  }
  for (const dataAutocloseDetails of document.querySelectorAll("details[data-autoclose-details]")) {
    if (dataAutocloseDetails.open && dataAutocloseDetails != activeDetails) {
      dataAutocloseDetails.open = false;
    }
  }
});

for (const dataDismissAlert of document.querySelectorAll("[data-dismiss-alert]")) {
  dataDismissAlert.addEventListener("click", function() {
    let parentElement = dataDismissAlert.parentElement;
    while (parentElement != null) {
      const role = parentElement.getAttribute("role");
      if (role != "alert") {
        parentElement = parentElement.parentElement;
        continue;
      }
      parentElement.style.transition = "opacity 100ms linear";
      parentElement.style.opacity = "0";
      setTimeout(function() { parentElement.style.display = "none" }, 100);
      return;
    }
  });
}

for (const dataGoBack of document.querySelectorAll("[data-go-back]")) {
  if (dataGoBack.tagName != "A") {
    continue;
  }
  dataGoBack.addEventListener("click", function(event) {
    if (document.referrer && history.length > 2 && !event.ctrlKey && !event.metaKey) {
      event.preventDefault();
      history.back();
    }
  });
}

for (const dataDisableClickSelection of document.querySelectorAll("[data-disable-click-selection]")) {
  dataDisableClickSelection.addEventListener("mousedown", function(event) {
    // https://stackoverflow.com/a/43321596
    if (event.detail > 1) {
      event.preventDefault();
    }
  });
}

for (const dataPaste of document.querySelectorAll("[data-paste]")) {
  let name = "";
  let isValidExt = {};
  try {
    const obj = JSON.parse(dataPaste.getAttribute("data-paste"));
    if (obj.name) {
      name = obj.name;
    }
    if (obj.ext) {
      for (let i = 0; i < obj.ext.length; i++) {
        const ext = obj.ext[i]
        isValidExt[ext] = true;
      }
    }
  } catch (e) {
    console.error(e);
    continue;
  }

  let form = null;
  let element = dataPaste.parentElement;
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
  const input = form.elements[name];
  if (!input || !(input instanceof HTMLInputElement) || input.type != "file") {
    continue;
  }

  dataPaste.addEventListener("paste", function(event) {
    event.preventDefault();
    let hasInvalidExt = false;
    for (let i = 0; i < event.clipboardData.files.length; i++) {
      const file = event.clipboardData.files.item(i);
      const n = file.name.lastIndexOf(".");
      const ext = n < 0 ? "" : file.name.substring(n);
      if (!isValidExt[ext]) {
        hasInvalidExt = true;
        break;
      }
    }
    if (!hasInvalidExt) {
      input.files = event.clipboardData.files;
      return;
    }
    let dataTransfer = new DataTransfer();
    let invalidCount = 0;
    for (let i = 0; i < event.clipboardData.files.length; i++) {
      const file = event.clipboardData.files.item(i);
      const n = file.name.lastIndexOf(".");
      const ext = n < 0 ? "" : file.name.substring(n);
      if (!isValidExt[ext]) {
        invalidCount++;
        continue;
      }
      dataTransfer.items.add(file);
    }
    if (invalidCount > 0) {
      dataPaste.value = `${invalidCount} invalid file${invalidCount == 1 ? "" : "s"}`;
      setTimeout(function() { dataPaste.value = "" }, 800);
    }
    input.files = dataTransfer.files;
  });
}
