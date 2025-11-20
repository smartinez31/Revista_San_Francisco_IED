import { state } from "./state.js";

export function saveDataToStorage() {
    localStorage.setItem("revista_users", JSON.stringify(state.users));
    localStorage.setItem("revista_articles", JSON.stringify(state.articles));
    localStorage.setItem("revista_notifications", JSON.stringify(state.notifications));
}

export function loadDataFromStorage() {
    const users = localStorage.getItem("revista_users");
    const articles = localStorage.getItem("revista_articles");
    const notifications = localStorage.getItem("revista_notifications");

    const backupUsers = [
        { id: 1, username: "admin", password: "admin", name: "Administrador", role: "admin" }
    ];

    const backupArticles = [
        {
            id: 1,
            title: "Bienvenido",
            category: "general",
            content: "Revista Digital Modo Offline",
            author: "Sistema",
            status: "published"
        }
    ];

    const backupNotifications = [
        {
            id: 1,
            title: "Modo Offline",
            content: "No hay conexión",
            type: "info"
        }
    ];

    state.users = users ? JSON.parse(users) : backupUsers;
    state.articles = articles ? JSON.parse(articles) : backupArticles;
    state.notifications = notifications ? JSON.parse(notifications) : backupNotifications;
}
