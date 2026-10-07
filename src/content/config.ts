import { defineCollection, z } from 'astro:content';

const emptyStringToUndefined = (val: unknown) =>
  typeof val === 'string' && val.trim() === '' ? undefined : val;

const blog = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.coerce.date(),
    updatedDate: z.preprocess(emptyStringToUndefined, z.coerce.date().optional()),
    heroImage: z.preprocess(emptyStringToUndefined, z.string().optional()),
    heroImageAlt: z.preprocess(emptyStringToUndefined, z.string().optional()),
    category: z.string(),
    tags: z.array(z.string()).default([]),
    readTime: z.string().default('৫ মিনিট'),
    author: z.preprocess(emptyStringToUndefined, z.string().optional()),
    draft: z.boolean().default(false),
  }),
});

export const collections = { blog };
