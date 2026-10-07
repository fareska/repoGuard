export function countPhrase(count: number, singular: string): string {
  return `${count} ${count === 1 ? singular : `${singular}s`}`;
}
