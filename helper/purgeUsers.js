import cron from "node-cron";

const purgeUsers = async (db) => {
  const batchSize = 1;
  const connection = await db.getConnection();
  let totalDeleted = 0;

  try {
    console.log("--- Starting Permanent Account Purge ---");

    while (true) {
      const [expiredAccounts] = await connection.execute(
       `SELECT account_id FROM tb_deleted_accounts
         WHERE deleted_at <= DATE_SUB(NOW(), INTERVAL 30 DAY) 
         LIMIT ${batchSize}`
      );

      console.log(expiredAccounts)

      if (expiredAccounts.length === 0) break;

      console.log(expiredAccounts[0])

      for (const { account_id } of expiredAccounts) {
        try {
          await connection.beginTransaction();

          await connection.execute(
            `DELETE FROM tb_gallery WHERE account_id = ?`,
            [account_id],
          );
          await connection.execute(
            `DELETE FROM tb_profile WHERE account_id = ?`,
            [account_id],
          );
          await connection.execute(
            `DELETE FROM tb_account WHERE account_id = ?`,
            [account_id],
          );

          // Delete from the tracking table so it's not picked up next loop
          await connection.execute(
            `DELETE FROM tb_deleted_accounts WHERE account_id = ?`,
            [account_id],
          );

          await connection.commit();
          totalDeleted++;
        } catch (innerError) {
          // If ONE account fails, rollback that one and keep going with others
          await connection.rollback();
          console.error(
            `Failed to purge account ${account_id}:`,
            innerError.message,
          );
        }
      }

      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    console.log(`Purge complete. Total records removed: ${totalDeleted}`);
    return totalDeleted;
  } catch (error) {
    console.error("Global Purge Error:", error.message);
  } finally {
    connection.release();
  }
};

const configureCron = (db) => {
  // "0 0 * * *" = Midnight every day.

  const schedule = "* * * * *"; // Runs every minute at the 0th second

  cron.schedule(schedule, () => {
    console.log("every minute");
    // purgeUsers(db).catch((err) =>
    //   console.error(`Cron Execution Error: ${err}`),
    // );
  });
};

export default configureCron;
