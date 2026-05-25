#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DemoChat Client v1.0
Красивый GUI клиент в стиле Telegram
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, simpledialog
import requests
import json
import threading
import time
from datetime import datetime
import hashlib
import os

# Настройки приложения
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

SERVER_URL = "http://127.0.0.1:5000"
API_BASE = f"{SERVER_URL}/api"

class AuthWindow(ctk.CTk):
    """Окно авторизации/регистрации"""
    
    def __init__(self):
        super().__init__()
        
        self.title("DemoChat - Вход")
        self.geometry("400x500")
        self.resizable(False, False)
        
        # Центрирование окна
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 400) // 2
        y = (self.winfo_screenheight() - 500) // 2
        self.geometry(f"400x500+{x}+{y}")
        
        self.token = None
        self.username = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Заголовок
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(pady=(40, 20))
        
        logo_label = ctk.CTkLabel(
            title_frame, 
            text="💬", 
            font=ctk.CTkFont(size=60)
        )
        logo_label.pack()
        
        title_label = ctk.CTkLabel(
            title_frame, 
            text="DemoChat", 
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.pack()
        
        subtitle_label = ctk.CTkLabel(
            title_frame, 
            text="Быстрый и безопасный мессенджер", 
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle_label.pack()
        
        # Форма
        form_frame = ctk.CTkFrame(self, fg_color="transparent")
        form_frame.pack(fill="both", expand=True, padx=30, pady=10)
        
        # Поле username
        self.username_entry = ctk.CTkEntry(
            form_frame,
            placeholder_text="Юзернейм (без @)",
            height=45,
            font=ctk.CTkFont(size=15),
            border_width=2,
            border_color="#3a3a3a"
        )
        self.username_entry.pack(fill="x", pady=(0, 15))
        
        # Поле password
        self.password_entry = ctk.CTkEntry(
            form_frame,
            placeholder_text="Пароль",
            show="•",
            height=45,
            font=ctk.CTkFont(size=15),
            border_width=2,
            border_color="#3a3a3a"
        )
        self.password_entry.pack(fill="x", pady=(0, 20))
        
        # Кнопка входа
        self.login_btn = ctk.CTkButton(
            form_frame,
            text="Войти",
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.login,
            fg_color="#2563eb",
            hover_color="#1d4ed8"
        )
        self.login_btn.pack(fill="x", pady=(0, 10))
        
        # Кнопка регистрации
        self.register_btn = ctk.CTkButton(
            form_frame,
            text="Создать аккаунт",
            height=40,
            font=ctk.CTkFont(size=14),
            command=self.register,
            fg_color="transparent",
            border_width=2,
            border_color="#2563eb",
            text_color="#2563eb",
            hover_color="#2563eb",
            hover_text_color="white"
        )
        self.register_btn.pack(fill="x")
        
        # Статус
        self.status_label = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="#ef4444"
        )
        self.status_label.pack(pady=(10, 20))
        
        # Проверка сервера
        self.check_server()
        
    def check_server(self):
        try:
            response = requests.get(f"{API_BASE}/status", timeout=3)
            if response.status_code == 200:
                self.status_label.configure(text="✅ Сервер подключен", text_color="#22c55e")
            else:
                self.status_label.configure(text="❌ Ошибка сервера", text_color="#ef4444")
        except:
            self.status_label.configure(text="❌ Сервер недоступен", text_color="#ef4444")
    
    def login(self):
        username = self.username_entry.get().strip().lstrip('@').lower()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_label.configure(text="⚠ Введите логин и пароль", text_color="#f59e0b")
            return
        
        try:
            response = requests.post(
                f"{API_BASE}/login",
                json={"username": username, "password": password},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("token")
                self.username = data.get("username")
                self.destroy()
            else:
                error = response.json().get("error", "Ошибка входа")
                self.status_label.configure(text=f"❌ {error}", text_color="#ef4444")
        except Exception as e:
            self.status_label.configure(text="❌ Ошибка соединения", text_color="#ef4444")
    
    def register(self):
        username = self.username_entry.get().strip().lstrip('@').lower()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_label.configure(text="⚠ Введите логин и пароль", text_color="#f59e0b")
            return
        
        if len(username) < 3 or len(username) > 20:
            self.status_label.configure(text="⚠ Юзернейм: 3-20 символов", text_color="#f59e0b")
            return
        
        try:
            response = requests.post(
                f"{API_BASE}/register",
                json={"username": username, "password": password},
                timeout=5
            )
            
            if response.status_code == 201:
                data = response.json()
                self.token = data.get("token")
                self.username = username
                self.status_label.configure(text="✅ Аккаунт создан! Вход...", text_color="#22c55e")
                self.after(1000, self.destroy)
            else:
                error = response.json().get("error", "Ошибка регистрации")
                self.status_label.configure(text=f"❌ {error}", text_color="#ef4444")
        except Exception as e:
            self.status_label.configure(text="❌ Ошибка соединения", text_color="#ef4444")


class ChatWindow(ctk.CTk):
    """Основное окно чата"""
    
    def __init__(self, token, username):
        super().__init__()
        
        self.token = token
        self.username = username
        self.messages = []
        self.current_chat = None
        self.polling = True
        
        self.title(f"DemoChat - @{username}")
        self.geometry("900x650")
        self.minsize(800, 600)
        
        # Центрирование
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 900) // 2
        y = (self.winfo_screenheight() - 650) // 2
        self.geometry(f"900x650+{x}+{y}")
        
        # Настройка сетки
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        self.setup_ui()
        self.start_polling()
        
        # Обработчик закрытия
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def setup_ui(self):
        # === Левая панель (список чатов) ===
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_rowconfigure(1, weight=1)
        
        # Заголовок sidebar
        sidebar_header = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=60)
        sidebar_header.grid(row=0, column=0, sticky="ew", padx=15, pady=(15, 10))
        sidebar_header.grid_columnconfigure(0, weight=1)
        
        user_label = ctk.CTkLabel(
            sidebar_header,
            text=f"👤 @{self.username}",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        user_label.grid(row=0, column=0, sticky="w")
        
        # Кнопка поиска
        search_btn = ctk.CTkButton(
            sidebar_header,
            text="🔍",
            width=40,
            height=35,
            command=self.search_user,
            fg_color="#3a3a3a",
            hover_color="#4a4a4a"
        )
        search_btn.grid(row=0, column=1, padx=(5, 0))
        
        # Список чатов
        self.chat_list_frame = ctk.CTkScrollableFrame(
            self.sidebar,
            fg_color="transparent",
            corner_radius=0
        )
        self.chat_list_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Нижняя панель sidebar
        sidebar_footer = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=50)
        sidebar_footer.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        
        logout_btn = ctk.CTkButton(
            sidebar_footer,
            text="Выйти",
            height=35,
            command=self.logout,
            fg_color="#dc2626",
            hover_color="#b91c1c"
        )
        logout_btn.pack(fill="x")
        
        # === Правая панель (чат) ===
        self.chat_panel = ctk.CTkFrame(self, corner_radius=0)
        self.chat_panel.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.chat_panel.grid_columnconfigure(0, weight=1)
        self.chat_panel.grid_rowconfigure(0, weight=1)
        
        # Заголовок чата
        self.chat_header = ctk.CTkFrame(self.chat_panel, height=60, fg_color="#252525")
        self.chat_header.grid(row=0, column=0, sticky="ew")
        self.chat_header.grid_columnconfigure(0, weight=1)
        
        self.chat_title_label = ctk.CTkLabel(
            self.chat_header,
            text="Выберите чат",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        self.chat_title_label.grid(row=0, column=0, sticky="w", padx=20, pady=15)
        
        self.chat_status_label = ctk.CTkLabel(
            self.chat_header,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="gray",
            anchor="w"
        )
        self.chat_status_label.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 15))
        
        # Область сообщений
        self.messages_frame = ctk.CTkScrollableFrame(
            self.chat_panel,
            fg_color="#1a1a1a",
            corner_radius=0
        )
        self.messages_frame.grid(row=1, column=0, sticky="nsew")
        
        # Поле ввода
        input_frame = ctk.CTkFrame(self.chat_panel, height=70, fg_color="#252525")
        input_frame.grid(row=2, column=0, sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)
        
        self.message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Напишите сообщение...",
            height=45,
            font=ctk.CTkFont(size=15),
            border_width=0,
            fg_color="#3a3a3a"
        )
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=15, pady=12)
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        send_btn = ctk.CTkButton(
            input_frame,
            text="➤",
            width=50,
            height=45,
            command=self.send_message,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(size=18)
        )
        send_btn.grid(row=0, column=1, padx=(10, 15), pady=12)
        
        # Приветственное сообщение
        self.show_welcome()
        
    def show_welcome(self):
        for widget in self.messages_frame.winfo_children():
            widget.destroy()
        
        welcome = ctk.CTkLabel(
            self.messages_frame,
            text="💬 Добро пожаловать в DemoChat!\n\nВыберите пользователя слева\nили найдите нового через 🔍",
            font=ctk.CTkFont(size=16),
            text_color="gray",
            justify="center"
        )
        welcome.pack(expand=True, pady=100)
        
    def search_user(self):
        dialog = ctk.CTkInputDialog(
            text="Введите юзернейм для поиска:",
            title="Поиск пользователя"
        )
        query = dialog.get_input()
        
        if not query or len(query.strip()) < 2:
            messagebox.showwarning("Поиск", "Введите минимум 2 символа")
            return
        
        try:
            response = requests.get(
                f"{API_BASE}/users/search",
                params={"q": query.strip().lstrip('@')},
                timeout=5
            )
            
            if response.status_code == 200:
                users = response.json()
                if users:
                    self.show_search_results(users)
                else:
                    messagebox.showinfo("Поиск", "Пользователи не найдены")
            else:
                messagebox.showerror("Ошибка", "Ошибка поиска")
        except Exception as e:
            messagebox.showerror("Ошибка", "Нет соединения с сервером")
    
    def show_search_results(self, users):
        # Создаем диалоговое окно с результатами
        result_window = ctk.CTkToplevel(self)
        result_window.title("Результаты поиска")
        result_window.geometry("400x300")
        result_window.resizable(False, False)
        
        frame = ctk.CTkFrame(result_window)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        title = ctk.CTkLabel(frame, text="Найденные пользователи:", font=ctk.CTkFont(size=14, weight="bold"))
        title.pack(pady=(0, 15))
        
        scroll_frame = ctk.CTkScrollableFrame(frame)
        scroll_frame.pack(fill="both", expand=True)
        
        for user in users:
            if user != self.username:
                btn = ctk.CTkButton(
                    scroll_frame,
                    text=f"@{user}",
                    height=40,
                    command=lambda u=user: self.select_chat(u, result_window),
                    fg_color="#3a3a3a",
                    hover_color="#2563eb"
                )
                btn.pack(fill="x", pady=5)
        
        if users == [self.username]:
            no_result = ctk.CTkLabel(scroll_frame, text="Только вы найдены", text_color="gray")
            no_result.pack(pady=20)
    
    def select_chat(self, username, close_window=None):
        self.current_chat = username
        self.chat_title_label.configure(text=f"@{username}")
        self.chat_status_label.configure(text="онлайн")
        
        if close_window:
            close_window.destroy()
        
        # Очищаем и загружаем сообщения
        for widget in self.messages_frame.winfo_children():
            widget.destroy()
        
        self.load_messages()
        
        # Добавляем чат в sidebar если нет
        self.add_chat_to_sidebar(username)
    
    def add_chat_to_sidebar(self, username):
        # Проверяем есть ли уже
        for widget in self.chat_list_frame.winfo_children():
            if hasattr(widget, 'chat_username') and widget.chat_username == username:
                return
        
        chat_btn = ctk.CTkButton(
            self.chat_list_frame,
            text=f"@{username}",
            height=50,
            command=lambda u=username: self.select_chat(u),
            fg_color="#2a2a2a",
            hover_color="#3a3a3a",
            anchor="w",
            padx=15
        )
        chat_btn.chat_username = username
        chat_btn.pack(fill="x", pady=2, padx=5)
        
        if self.current_chat == username:
            chat_btn.configure(fg_color="#2563eb")
    
    def load_messages(self):
        if not self.current_chat:
            return
        
        try:
            response = requests.get(
                f"{API_BASE}/messages",
                headers=self.headers,
                timeout=5
            )
            
            if response.status_code == 200:
                all_messages = response.json()
                # Фильтруем только для текущего чата
                chat_messages = [m for m in all_messages if m['sender'] == self.current_chat]
                
                self.display_messages(chat_messages)
        except Exception as e:
            print(f"Ошибка загрузки: {e}")
    
    def display_messages(self, messages):
        for widget in self.messages_frame.winfo_children():
            widget.destroy()
        
        if not messages:
            no_msgs = ctk.CTkLabel(
                self.messages_frame,
                text="Нет сообщений\nНачните общение!",
                font=ctk.CTkFont(size=14),
                text_color="gray",
                justify="center"
            )
            no_msgs.pack(expand=True, pady=50)
            return
        
        # Группируем по датам
        prev_date = None
        for msg in messages:
            msg_date = datetime.fromtimestamp(msg['ts']).strftime('%d.%m.%Y')
            
            if msg_date != prev_date:
                date_label = ctk.CTkLabel(
                    self.messages_frame,
                    text=msg_date,
                    font=ctk.CTkFont(size=11),
                    text_color="gray",
                    bg_color="#1a1a1a"
                )
                date_label.pack(pady=10)
                prev_date = msg_date
            
            is_mine = msg['sender'] == self.username
            
            msg_frame = ctk.CTkFrame(self.messages_frame, fg_color="transparent")
            msg_frame.pack(fill="x", padx=10, pady=2)
            
            bubble_color = "#2563eb" if is_mine else "#3a3a3a"
            anchor = "e" if is_mine else "w"
            
            bubble = ctk.CTkFrame(
                msg_frame,
                fg_color=bubble_color,
                corner_radius=15,
                width=0
            )
            bubble.pack(anchor=anchor)
            
            text_label = ctk.CTkLabel(
                bubble,
                text=msg['text'],
                font=ctk.CTkFont(size=14),
                wraplength=400,
                justify="left",
                padx=15,
                pady=10
            )
            text_label.pack()
            
            time_str = datetime.fromtimestamp(msg['ts']).strftime('%H:%M')
            time_label = ctk.CTkLabel(
                bubble,
                text=time_str,
                font=ctk.CTkFont(size=10),
                text_color="white" if is_mine else "gray"
            )
            time_label.pack(anchor="se" if is_mine else "sw", padx=10, pady=(0, 5))
        
        # Прокрутка вниз
        self.messages_frame._scrollbar.set(1.0)
    
    def send_message(self):
        if not self.current_chat:
            messagebox.showwarning("Чат", "Выберите собеседника")
            return
        
        text = self.message_entry.get().strip()
        if not text:
            return
        
        if len(text) > 8192:
            messagebox.showerror("Ошибка", "Сообщение слишком длинное")
            return
        
        try:
            response = requests.post(
                f"{API_BASE}/send",
                headers=self.headers,
                json={"to": self.current_chat, "text": text},
                timeout=5
            )
            
            if response.status_code == 200:
                self.message_entry.delete(0, 'end')
                self.load_messages()
            else:
                error = response.json().get("error", "Ошибка отправки")
                messagebox.showerror("Ошибка", error)
        except Exception as e:
            messagebox.showerror("Ошибка", "Нет соединения с сервером")
    
    def start_polling(self):
        def poll():
            while self.polling:
                try:
                    if self.current_chat:
                        self.load_messages()
                except:
                    pass
                time.sleep(3)
        
        thread = threading.Thread(target=poll, daemon=True)
        thread.start()
    
    def logout(self):
        if messagebox.askyesno("Выход", "Вы уверены?"):
            self.polling = False
            self.destroy()
    
    def on_close(self):
        self.polling = False
        self.destroy()


def main():
    # Окно авторизации
    auth = AuthWindow()
    auth.mainloop()
    
    # Если успешная авторизация
    if auth.token and auth.username:
        chat = ChatWindow(auth.token, auth.username)
        chat.mainloop()


if __name__ == "__main__":
    main()
