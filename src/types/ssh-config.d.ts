declare module 'ssh-config' {
  export function parse(content: string): any;
  const _default: {
    parse: typeof parse;
  };
  export default _default;
}
