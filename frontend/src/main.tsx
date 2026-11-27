import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/tokens.css'
import './styles/app.css'
import App from './App'

// Apply persisted theme and locale before initial paint without inline HTML scripts (strict CSP safe).
try {
  const savedTheme = localStorage.getItem('veilink_theme')
  if (savedTheme === 'light' || savedTheme === 'dark') {
    document.documentElement.dataset.theme = savedTheme
  }
  const savedLocale = localStorage.getItem('veilink_locale')
  if (savedLocale) {
    document.documentElement.lang = savedLocale
    document.documentElement.dir = savedLocale === 'ar' ? 'rtl' : 'ltr'
  }
} catch { /* ignore */ }

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
