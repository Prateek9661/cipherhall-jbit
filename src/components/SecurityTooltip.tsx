import React from 'react';

interface SecurityTooltipProps {
  text: string;
  align?: 'left' | 'right' | 'center';
  position?: 'top' | 'bottom';
  children: React.ReactNode;
}

export function SecurityTooltip({
  text,
  align = 'center',
  position = 'bottom',
  children,
}: SecurityTooltipProps) {
  const alignClasses =
    align === 'right'
      ? 'right-0'
      : align === 'left'
      ? 'left-0'
      : 'left-1/2 -translate-x-1/2';

  const positionClasses =
    position === 'top' ? 'bottom-full mb-2' : 'top-full mt-2';

  return (
    <span
      className="relative inline-flex items-center group focus-within:z-30 hover:z-30"
      title={text}
    >
      {children}
      <span
        role="tooltip"
        className={`pointer-events-none opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity duration-150 absolute ${positionClasses} ${alignClasses} z-40 w-64 px-3 py-2 rounded-lg bg-[#0E1420] border border-slate-700/90 shadow-xl text-left text-xs font-normal leading-relaxed text-slate-200 whitespace-normal`}
      >
        {text}
      </span>
    </span>
  );
}
