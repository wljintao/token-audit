<script setup lang="ts">
import IntroSection from "./components/IntroSection.vue";
import AuditSection from "./components/AuditSection.vue";
import ProfileSection from "./components/ProfileSection.vue";
import FaqSection from "./components/FaqSection.vue";

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
}
</script>

<template>
  <div>
    <nav class="nav">
      <div class="nav__inner">
        <span class="nav__brand">
          <span class="nav__logo">TA</span>
          <span class="nav__name">Token Audit</span>
        </span>

        <a class="nav__github" href="https://github.com/wljintao/token-audit" target="_blank" rel="noopener noreferrer">
          <svg class="nav__github-icon" width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2-2.26.46-3.01-.95-3.01-.95-.34-.78-.84-1.05-.84-1.05-.69-.47.05-.46.05-.46.76.05 1.16.78 1.16.78.68 1.17 1.79.83 2.23.63.07-.49.27-.83.49-1.02-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.67 7.67 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
          </svg>
          GitHub
        </a>
      </div>
    </nav>

    <main class="app">
      <IntroSection @start="scrollTo('audit')" @report="scrollTo('profile')" />
      <AuditSection />
      <ProfileSection />
      <FaqSection />
    </main>

    <footer class="app__footer">
      <div class="app__footer-inner">&copy; 2026 <a class="app__footer-link" href="https://www.anyllm.cc" target="_blank" rel="noopener noreferrer">AnyLLM</a> · Token Audit for OpenAI-compatible relays</div>
    </footer>
  </div>
</template>
