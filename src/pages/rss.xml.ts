import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIContext } from 'astro';

export async function GET(context: APIContext) {
  const posts = await getCollection('blog', ({ data }) => !data.draft);
  const sortedPosts = posts.sort((a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf());

  return rss({
    title: 'মুহাম্মদ ইয়াহিয়া | প্রযুক্তি ও জীবনবোধের কথকতা',
    description: 'মুহাম্মদ ইয়াহিয়ার ব্যক্তিগত ব্লগ। সফটওয়্যার আর্কিটেকচার, ভ্রমণ ডায়েরি এবং জীবনদর্শন নিয়ে বাংলা লেখালেখি।',
    site: context.site || 'https://yahya.bd',
    items: sortedPosts.map((post) => ({
      title: post.data.title,
      pubDate: post.data.pubDate,
      description: post.data.description,
      link: `/blog/${post.slug}/`,
      categories: [post.data.category, ...post.data.tags],
    })),
    customData: `<language>bn</language>`,
  });
}
