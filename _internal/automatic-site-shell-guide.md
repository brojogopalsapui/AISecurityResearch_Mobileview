# Automatic site shell guide

This repo now uses a shared JavaScript shell for the repeated top navigation and footer.

## Main idea

Instead of manually editing the same header/footer in every HTML file, the shared shell is injected from:

- `assets/js/site-shell.js`

Each page keeps only its page-specific content.

## Page metadata used by the shell

Every page body now includes:

- `data-site-root` → relative path back to repo root (`""` for root pages, `"../"` for pages inside folders)
- `data-nav` → which navigation item should appear active
- `data-show-topbar="true"` → only used on the homepage right now

## To create a new page

1. Copy an existing page that is closest in style.
2. Keep the line:
   - `<script src=".../assets/js/site-shell.js"></script>`
3. Keep the line:
   - `<script src=".../assets/js/main.js"></script>`
4. Update the `<body>` attributes:
   - root page: `data-site-root=""`
   - page inside a folder: `data-site-root="../"`
5. Set `data-nav` to one of:
   - `home`
   - `about`
   - `research`
   - `trending`
   - `resources`
   - `contact`
6. Keep only page-specific `<main> ... </main>` content.

## Which pages should use which nav value

- `index.html` → `home`
- `about.html` → `about`
- `research.html` → `research`
- `ongoing-work.html` and all `posts/*.html` → `trending`
- `publications.html` → `resources`
- `contact.html` → `contact`
- `ai-security/*.html` and `ai-foundations/*.html` → `research`

## Single place to update navigation and footer

Edit only:

- `assets/js/site-shell.js`

That file controls:

- brand link
- main navigation
- homepage topbar
- shared footer
