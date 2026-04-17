import { UI } from "../ui"
import { cmd } from "./cmd"
import { Instance } from "@/project/instance"
import { Process } from "@/util/process"
import { git } from "@/util/git"

export const PrCommand = cmd({
  command: "pr <number>",
  describe: "fetch and checkout a GitHub PR branch, then run numasec",
  builder: (yargs) =>
    yargs.positional("number", {
      type: "number",
      describe: "PR number to checkout",
      demandOption: true,
    }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        const project = Instance.project
        if (project.vcs !== "git") {
          UI.error("Could not find git repository. Please run this command from a git repository.")
          process.exit(1)
        }

        const prNumber = args.number
        const localBranchName = `pr/${prNumber}`
        UI.println(`Fetching and checking out PR #${prNumber}...`)

        // Use gh pr checkout with custom branch name
        const result = await Process.run(
          ["gh", "pr", "checkout", `${prNumber}`, "--branch", localBranchName, "--force"],
          {
            nothrow: true,
          },
        )

        if (result.code !== 0) {
          UI.error(`Failed to checkout PR #${prNumber}. Make sure you have gh CLI installed and authenticated.`)
          process.exit(1)
        }

        // Fetch PR info for fork handling
        const prInfoResult = await Process.text(
          [
            "gh",
            "pr",
            "view",
            `${prNumber}`,
            "--json",
            "headRepository,headRepositoryOwner,isCrossRepository,headRefName",
          ],
          { nothrow: true },
        )

        if (prInfoResult.code === 0) {
          const prInfoText = prInfoResult.text
          if (prInfoText.trim()) {
            const prInfo = JSON.parse(prInfoText)

            // Handle fork PRs
            if (prInfo && prInfo.isCrossRepository && prInfo.headRepository && prInfo.headRepositoryOwner) {
              const forkOwner = prInfo.headRepositoryOwner.login
              const forkName = prInfo.headRepository.name
              const remoteName = forkOwner

              // Check if remote already exists
              const remotes = (await git(["remote"], { cwd: Instance.worktree })).text().trim()
              if (!remotes.split("\n").includes(remoteName)) {
                await git(["remote", "add", remoteName, `https://github.com/${forkOwner}/${forkName}.git`], {
                  cwd: Instance.worktree,
                })
                UI.println(`Added fork remote: ${remoteName}`)
              }

              // Set upstream to the fork so pushes go there
              await git(["branch", `--set-upstream-to=${remoteName}/${prInfo.headRefName}`, localBranchName], {
                cwd: Instance.worktree,
              })
            }
          }
        }

        UI.println(`Successfully checked out PR #${prNumber} as branch '${localBranchName}'`)
        UI.println()
        UI.println("Starting numasec...")
        UI.println()

        const numasecProcess = Process.spawn(["numasec"], {
          stdin: "inherit",
          stdout: "inherit",
          stderr: "inherit",
          cwd: process.cwd(),
        })
        const code = await numasecProcess.exited
        if (code !== 0) throw new Error(`numasec exited with code ${code}`)
      },
    })
  },
})
