# Advanced Todo Application

An advanced, secure, and feature-rich todo application built with the MERN stack. This application supports detailed task management with scheduling, reminders, step-by-step instructions, archiving, soft deletion, and cascade deletion of related data.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [System Architecture & Data Flow](#system-architecture--data-flow)
- [Database Schemas](#database-schemas)
- [Cascade Deletion & Background Jobs](#cascade-deletion--background-jobs)
- [Project Structure](#project-structure)
- [Deployment & Operational Considerations](#deployment--operational-considerations)
- [Summary](#summary)

---

## Project Overview

**Project Name:** Advanced Todo Application (MERN Stack)  
**Objective:**  
Build a highly functional, secure, and user-friendly todo application with advanced features such as scheduling, reminders, step management, archiving, soft deletion, and automated cascade deletion—all accessible only by authenticated users.

---

## Features

### Authentication & Authorization

- **JWT Authentication:**
  - Users can sign up and log in.
  - JWT tokens are generated and securely stored in cookies.
  - Only authenticated users can perform CRUD operations on todos.

### Todo Management

- **Creation & Update:**
  - Create todos with a title, notes/short description, and additional details.
  - Set a default due date (e.g., 2 days from creation) that is modifiable.
  - Mark todos as important.
  - Assign a schedule/plan date for future tasks.
- **Steps Integration:**
  - Each todo can include an array of step IDs.
  - Steps are maintained as separate documents, each containing an order field to enforce the correct sequence of completion.
- **Reminder Functionality:**

  - Option to enable daily email reminders until the due date.
  - A field (`reminderSentAt`) tracks the last reminder sent to avoid duplicate notifications.

- **Status Management:**
  - Todos can have three statuses:
    - **Active:** Task is ongoing.
    - **Completed:** Task has been finished.
    - **Not Completed:** Automatically updated if the due date passes without completion.

### Searching, Sorting & Filtering

- **Search:**
  - Keyword search based on the todo title.
- **Sorting:**
  - Sort by new-to-old, old-to-new.
  - Sort by title (ascending/descending).
- **Filtering:**
  - Filter by status (active, completed, not completed).
  - Filter by importance.
  - Filter by scheduled date or creation date.
  - Filter for active todos (pending tasks not yet completed within the due date).

### Archiving & Deletion

- **Archiving:**

  - Todos can be archived for later restoration.
  - Archived todos are moved to a dedicated Archive collection.

- **Soft Deletion (Trash):**

  - When a todo is deleted, it is moved to a “Trash” collection instead of being immediately removed.
  - The Trash document stores a reference to its associated step IDs.
  - A TTL index on the Trash collection purges items automatically after 7 days.

- **Cascade Deletion:**
  - A background process ensures that once a todo is permanently removed from Trash, its associated steps are also deleted.
  - Since MongoDB’s TTL deletion bypasses Mongoose middleware, a scheduled function (running every 10 minutes) handles the cleanup of related steps.

---

## Technology Stack

- **Frontend:**

  - React for a dynamic user interface.
  - (Optional: Redux or Context API for state management.)

- **Backend:**
  - Node.js with Express for the server.
  - JWT for authentication and authorization.
- **Database:**
  - MongoDB with Mongoose ODM.
  - Collections include: Users, Todos, Steps, Archive, and Trash.
- **Other Tools/Services:**
  - Email service (e.g., NodeMailer or SendGrid) for reminder notifications.
  - Scheduling: Using `setInterval` (or a library like node-cron) for cascade deletion and reminder notifications.

---

## System Architecture & Data Flow

1. **User Authentication:**

   - Users register or log in, receiving a JWT stored in a secure cookie.
   - All subsequent operations require valid JWT authentication.

2. **Todo Operations:**

   - **Creation/Update:**
     - Users create todos with details like title, notes, due date, schedule date, and optional reminder.
     - Steps are created as separate documents and linked via an array of step IDs.
   - **Reminder Process:**
     - A background job sends daily reminder emails until the due date is reached.
     - The `reminderSentAt` field ensures no duplicate reminders are sent on the same day.
   - **Status Update:**
     - The system auto-updates the todo status to “not completed” if the due date passes without completion.

3. **Search, Sort, & Filter:**

   - Endpoints support keyword searches, sorting (by creation date or title), and filtering based on status, importance, and dates.

4. **Archiving & Deletion:**
   - **Archiving:**
     - Todos can be archived and restored from the Archive collection.
   - **Soft Deletion (Trash):**
     - Deleted todos move to the Trash collection, retaining references to their steps.
     - The Trash document’s `deletedAt` field (with a TTL of 7 days) automatically purges the document after 7 days.
   - **Cascade Deletion:**
     - A scheduled function checks for expired trash items and deletes associated steps from the Steps collection.

---

## Database Schemas

### User Schema

- **Fields:**
  - `username`, `email` (unique), `password` (hashed).
  - Timestamps for creation and updates.

### Todo Schema

- **Fields:**
  - `user` (reference to User).
  - `title`, `notes`, `isImportant`, `scheduleDate`, `dueDate` (default: 2 days from creation), `reminder`, `reminderSentAt`, `status`.
  - `steps`: Array of step IDs (referencing the Steps collection).

### Step Schema

- **Fields:**
  - `todo` (reference to parent Todo).
  - `description`, `isCompleted`, `order` (to manage the sequence).

### Archive Schema

- **Fields:**
  - Stores a copy of the todo details (including step references) with an archived timestamp.

### Trash Schema

- **Fields:**
  - Contains the original todo’s details and an array of step IDs.
  - `deletedAt`: Date with a TTL index set to expire documents after 7 days.

```
react-todo
├─ backend
│  ├─ .env
│  ├─ jsconfig.json
│  ├─ notes.txt
│  ├─ package-lock.json
│  ├─ package.json
│  └─ src
│     ├─ controllers
│     │  └─ authController.js
│     ├─ index.js
│     ├─ middlewares
│     ├─ models
│     │  ├─ archiveTodo-model.js
│     │  ├─ step-model.js
│     │  ├─ todo-model.js
│     │  ├─ trashTodo-model.js
│     │  └─ user-model.js
│     ├─ routes
│     │  ├─ todoRoutes.js
│     │  └─ userRoutes.js
│     ├─ services
│     │  └─ dbConnect.js
│     └─ utils
│        └─ cascadeRemoval.js
└─ frontend
   ├─ eslint.config.js
   ├─ index.html
   ├─ package-lock.json
   ├─ package.json
   ├─ postcss.config.js
   ├─ public
   │  ├─ vite.svg
   │  └─ witch.png
   ├─ README.md
   ├─ src
   │  ├─ App.css
   │  ├─ App.jsx
   │  ├─ assets
   │  │  ├─ add.svg
   │  │  ├─ calendar.svg
   │  │  ├─ caret-down.svg
   │  │  ├─ close.svg
   │  │  ├─ delete.svg
   │  │  ├─ due-date.svg
   │  │  ├─ Icon.svg
   │  │  ├─ Icon2.svg
   │  │  ├─ Icon3.svg
   │  │  ├─ info.svg
   │  │  ├─ list.svg
   │  │  ├─ logomark.svg
   │  │  ├─ menu.svg
   │  │  ├─ moon.svg
   │  │  ├─ notifications.svg
   │  │  ├─ people.svg
   │  │  ├─ planned.svg
   │  │  ├─ react.svg
   │  │  ├─ repeat.svg
   │  │  ├─ star-fill.svg
   │  │  ├─ star.svg
   │  │  ├─ sun.svg
   │  │  └─ Vector.svg
   │  ├─ components
   │  │  ├─ edit-todo
   │  │  │  ├─ TodoEdit.jsx
   │  │  │  └─ TodoEditFooter.jsx
   │  │  ├─ header
   │  │  │  ├─ Grid.jsx
   │  │  │  ├─ Header.jsx
   │  │  │  ├─ Search.jsx
   │  │  │  └─ ThemSwitcher.jsx
   │  │  ├─ ProtectedRoute.jsx
   │  │  ├─ sidebar
   │  │  │  ├─ AddList.jsx
   │  │  │  ├─ Donut.jsx
   │  │  │  ├─ Sidebar.jsx
   │  │  │  ├─ TaskOverView.jsx
   │  │  │  └─ TasksNav.jsx
   │  │  └─ todo-container
   │  │     ├─ AddTodo.jsx
   │  │     ├─ Completed.jsx
   │  │     ├─ Inprogress.jsx
   │  │     ├─ Todo.jsx
   │  │     └─ TodoContainer.jsx
   │  ├─ context
   │  │  ├─ EditContext.jsx
   │  │  ├─ ThemeContext.jsx
   │  │  └─ VIewContext.jsx
   │  ├─ index.css
   │  ├─ main.jsx
   │  ├─ pages
   │  │  ├─ LoginPage.jsx
   │  │  ├─ RegisterPage.jsx
   │  │  └─ TodoPage.jsx
   │  └─ utils
   │     └─ auth.js
   ├─ tailwind.config.js
   └─ vite.config.js

```
