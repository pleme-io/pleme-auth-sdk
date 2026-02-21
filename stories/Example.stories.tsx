import type { Meta, StoryObj } from '@storybook/react';
import { Example } from '../src/Example';

const meta = {
  title: 'Components/Example',
  component: Example,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
  argTypes: {
    title: {
      control: 'text',
      description: 'The title to display',
    },
    onClick: {
      action: 'clicked',
      description: 'Callback when clicked',
    },
  },
} satisfies Meta<typeof Example>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    title: 'Example Component',
  },
};

export const CustomTitle: Story = {
  args: {
    title: 'Custom Title',
  },
};

export const WithClick: Story = {
  args: {
    title: 'Click Me!',
    onClick: () => alert('Clicked!'),
  },
};
