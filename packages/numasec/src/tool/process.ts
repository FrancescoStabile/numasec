export type RunResult = { argv: string[]; stdout: string; stderr: string; exitCode: number }

export async function runProcess(argv: string[]): Promise<RunResult> {
  const proc = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe" })
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])
  const exitCode = await proc.exited
  return { argv, stdout, stderr, exitCode }
}
