"use strict";

const urlInput = document.querySelector("#url");
const charCount = document.querySelector("#char-count");

if (urlInput && charCount) {
    const updateCount = () => {
        charCount.textContent = `${urlInput.value.length} / 2048`;
    };
    urlInput.addEventListener("input", updateCount);
    updateCount();

    document.querySelectorAll("[data-example]").forEach((button) => {
        button.addEventListener("click", () => {
            urlInput.value = button.dataset.example;
            updateCount();
            urlInput.focus();
        });
    });
}
