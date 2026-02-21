import { memo, forwardRef } from 'react';
import type { ExampleProps } from './types';

/**
 * Example component
 *
 * This is a placeholder component that demonstrates the library structure.
 * Replace this with your actual component implementation.
 *
 * @example
 * ```tsx
 * <Example title="Hello World" onClick={() => console.log('clicked')} />
 * ```
 */
export const Example = memo(
  forwardRef<HTMLDivElement, ExampleProps>(
    ({ title = 'Example Component', onClick }, ref) => {
      return (
        <div ref={ref} onClick={onClick}>
          <h1>{title}</h1>
          <p>This is an example component from a TypeScript library.</p>
        </div>
      );
    }
  )
);

Example.displayName = 'Example';
