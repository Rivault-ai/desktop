import { useId } from 'react'
import { cn } from '@/lib/utils'

interface RivaultLogoProps {
  size?: number
  className?: string
}

export function RivaultIcon({ size = 28, className }: RivaultLogoProps) {
  const uid = useId()
  const bg = `ri_bg_${uid}`
  const bg2 = `ri_bg2_${uid}`
  const lock = `ri_lock_${uid}`
  const circle = `ri_circle_${uid}`
  const clip = `ri_clip_${uid}`

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 305 305"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('shrink-0', className)}
    >
      <rect width="304.865" height="304.865" rx="52.765" fill={`url(#${bg})`} />
      <g clipPath={`url(#${clip})`}>
        <rect width="304.865" height="304.865" rx="52.765" fill={`url(#${bg2})`} />
        <path
          d="M185.866 371.324V144.604C185.866 127.6 172.209 113.815 155.364 113.815C138.518 113.815 124.861 127.6 124.861 144.604V371.324C124.861 388.328 138.518 402.113 155.364 402.113V474.887C98.6999 474.887 52.7649 428.52 52.7649 371.324V144.604C52.7649 87.4078 98.6999 41.041 155.364 41.041C212.027 41.041 257.962 87.4078 257.962 144.604V371.324L257.93 373.997C256.525 429.958 211.142 474.887 155.364 474.887V402.113C172.209 402.113 185.866 388.328 185.866 371.324Z"
          fill={`url(#${lock})`}
        />
        <path
          d="M237.944 319.524C237.944 273.916 200.972 236.943 155.364 236.943C109.756 236.943 72.783 273.916 72.783 319.524C72.783 365.132 109.756 402.105 155.364 402.105V474.887C69.5587 474.887 0 405.329 0 319.524C0 233.719 69.5587 164.16 155.364 164.16C241.169 164.16 310.727 233.719 310.727 319.524C310.727 405.329 241.169 474.887 155.364 474.887V402.105C200.972 402.105 237.944 365.132 237.944 319.524Z"
          fill={`url(#${circle})`}
        />
      </g>
      <defs>
        <radialGradient id={bg} cx="0" cy="0" r="1" gradientTransform="matrix(333.136 318.845 -318.845 797.612 0 -7.441)" gradientUnits="userSpaceOnUse">
          <stop stopColor="#EAFF00" />
          <stop offset="0.186" stopColor="#A6FF00" />
          <stop offset="0.673" stopColor="#D1FF00" />
          <stop offset="1" stopColor="#AAFF00" />
        </radialGradient>
        <radialGradient id={bg2} cx="0" cy="0" r="1" gradientTransform="matrix(333.136 318.845 -318.845 797.612 0 -7.441)" gradientUnits="userSpaceOnUse">
          <stop stopColor="#EAFF00" />
          <stop offset="0.186" stopColor="#A6FF00" />
          <stop offset="0.673" stopColor="#D1FF00" />
          <stop offset="1" stopColor="#AAFF00" />
        </radialGradient>
        <linearGradient id={lock} x1="155.364" y1="41.041" x2="155.364" y2="474.887" gradientUnits="userSpaceOnUse">
          <stop stopColor="#081C00" />
          <stop offset="1" stopColor="#154B00" />
        </linearGradient>
        <linearGradient id={circle} x1="155.364" y1="164.16" x2="155.364" y2="474.887" gradientUnits="userSpaceOnUse">
          <stop stopColor="#081C00" />
          <stop offset="1" stopColor="#154B00" />
        </linearGradient>
        <clipPath id={clip}>
          <rect width="304.865" height="304.865" rx="52.765" fill="white" />
        </clipPath>
      </defs>
    </svg>
  )
}

export function RivaultLogo({ size = 28, className }: RivaultLogoProps) {
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <RivaultIcon size={size} />
      <span className="font-semibold tracking-tight">Rivault</span>
    </div>
  )
}
