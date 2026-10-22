import { createHash } from 'node:crypto';

/** Portrait on Wikimedia Commons (File: name without the prefix). */
export const PORTRAIT_FILE = 'Muhammad Yahya - WikiConference India 2026 - Day 1 2026-09-04.jpg';

/**
 * Thumbnail widths Wikimedia serves to hotlinkers; any other width is rejected with HTTP 400.
 * https://www.mediawiki.org/wiki/Common_thumbnail_sizes
 */
const COMMONS_THUMB_WIDTHS = [20, 40, 60, 120, 250, 330, 500, 960, 1280, 1920, 3840];

/**
 * Build the upload.wikimedia.org thumbnail URL for a Commons file at the given width.
 * Commons shards files by the first two hex digits of the MD5 of the underscored name.
 */
export function commonsThumb(file: string, width: (typeof COMMONS_THUMB_WIDTHS)[number]): string {
  if (!COMMONS_THUMB_WIDTHS.includes(width)) {
    throw new Error(`commonsThumb: ${width}px is not a standard Commons width (${COMMONS_THUMB_WIDTHS.join(', ')})`);
  }
  const name = file.trim().replace(/ /g, '_');
  const hash = createHash('md5').update(name).digest('hex');
  const encoded = encodeURIComponent(name);
  return `https://upload.wikimedia.org/wikipedia/commons/thumb/${hash[0]}/${hash.slice(0, 2)}/${encoded}/${width}px-${encoded}`;
}
