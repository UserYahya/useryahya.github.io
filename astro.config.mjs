import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import sitemap from '@astrojs/sitemap';
import { readdirSync, readFileSync } from 'node:fs';

// Map each blog post URL to its last-modified date so the sitemap carries <lastmod>
const blogDir = new URL('./src/content/blog/', import.meta.url);
const postDates = new Map(
  readdirSync(blogDir)
    .filter((file) => file.endsWith('.md') || file.endsWith('.mdx'))
    .map((file) => {
      const source = readFileSync(new URL(file, blogDir), 'utf-8');
      const field = (name) => source.match(new RegExp(`^${name}:\s*["']?([^"'\r\n]+)`, 'm'))?.[1];
      const slug = field('slug') || file.replace(/\.mdx?$/, '');
      const date = field('updatedDate') || field('pubDate');
      return [`https://yahya.bd/blog/${slug}/`, date?.trim().slice(0, 10)];
    })
);

// https://astro.build/config
export default defineConfig({
  site: 'https://yahya.bd',
  base: '/',
  integrations: [
    tailwind({
      applyBaseStyles: false,
    }),
    sitemap({
      filter: (page) => !page.includes('/admin/'),
      serialize(item) {
        const lastmod = postDates.get(item.url);
        if (lastmod && /^\d{4}-\d{2}-\d{2}$/.test(lastmod)) item.lastmod = lastmod;
        return item;
      },
    }),
  ],
});
