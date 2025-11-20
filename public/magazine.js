import { state } from "./state.js";
import { showPage } from "./navigation.js";

export function loadPublicMagazine() {
    renderPublicMagazine(state.articles);
}

export function renderPublicMagazine(articles) {
    const cont = document.getElementById("public-magazine-content");
    cont.innerHTML = "";

    if (articles.length === 0) {
        cont.innerHTML = `<p>No hay artículos disponibles</p>`;
        return;
    }

    articles.forEach(a => {
        const box = document.createElement("div");
        box.className = "article-card";

        box.innerHTML = `
            <h3>${a.title}</h3>
            <p>${a.content.substring(0, 120)}...</p>
            <button onclick="showArticle(${a.id})">Leer más</button>
        `;

        cont.appendChild(box);
    });
}

export function showArticle(id) {
    const art = state.articles.find(a => a.id === id);
    if (!art) return;

    const main = document.getElementById("main-content");

    main.innerHTML = `
        <button onclick="showPage('public-magazine-page')">Volver</button>
        <h2>${art.title}</h2>
        <p>${art.content}</p>
    `;

    showPage("public-magazine-page");
}
