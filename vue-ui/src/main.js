import { createApp } from 'vue'
import { createI18n } from 'vue-i18n'
import App from './App.vue'
import './styles/ios.css'

import zhMessages from './locales/zh.json'
import faMessages from './locales/fa.json'

// Detect browser language
const browserLang = navigator.language || navigator.userLanguage || ''
const savedLang = localStorage.getItem('preferredLanguage') || ''
let defaultLocale = 'zh'

if (savedLang === 'fa' || savedLang === 'fa-IR') {
  defaultLocale = 'fa'
} else if (savedLang === 'zh' || savedLang === 'zh-CN') {
  defaultLocale = 'zh'
} else if (browserLang.includes('fa')) {
  defaultLocale = 'fa'
}

const i18n = createI18n({
  legacy: false,
  locale: defaultLocale,
  fallbackLocale: 'zh',
  messages: {
    zh: zhMessages,
    fa: faMessages
  }
})

const app = createApp(App)
app.use(i18n)
app.mount('#app')
