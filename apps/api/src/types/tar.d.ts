declare module 'tar' {
  interface ReadEntry {
    path: string;
    type: string;
    size: number;
  }

  interface TarModule {
    t(options: { file: string; onentry: (entry: ReadEntry) => void }): Promise<void>;
    x(options: {
      file: string;
      cwd: string;
      strip: number;
      strict: boolean;
      filter: (entryPath: string, entry: ReadEntry) => boolean;
    }): Promise<void>;
  }

  const tar: TarModule;
  export default tar;
}
