CRIMSON DESERT MULTIPLAYER - CO-OP (TEST VERSION)
=================================================

Two players in one world: the world is the HOST's, and the GUEST joins it with their own character.
This is an unofficial mod. Use it at your own risk.

THIS ZIP IS FOR 1.0.0.3663 (Steam's update of 13 November 2026, evening). Both PCs need that version. 3663 changed a
lot inside the game, so the mod was ported to it again. On 3663, with two copies of the game on one PC, these were
checked: JOINING (the guest loads into the host's world), the guest going back to the title and JOINING AGAIN, the
weather, SHIPS (the host sailing with the guest on board, see below), the HOST'S HOUSE as the guest sees it (the
whole house and the pets; the building mode was not tried), SHOPKEEPERS (Delkin in Hernand: the guest opened the
shop, bought a Water with its own money, sold it back and left) and MARKET STALLS (the guest bought a Harvest Sack
and a Rosemary from two stalls, holding E), with no error. Not tried on 3663 yet: mounts and fighting; please tell
us if something that worked before no longer does. Looks only: next to the host's house the guest's ground looked
wet (puddles) while the host's was dry. And the guest always shows the HOST's weather and daylight as the host's own
camera has them: while the host is outdoors, a room the guest walks into is lit like the outdoors (a blue tint), and
while the host is inside a building the guest's sky may look dimmer. It matches again when you are in the same place.

Checked on 1.0.0.3576 (the version before), with two copies of the game on one PC: joining, the guest going back to
the title and joining again, SHOPKEEPERS (Delkin: the menu and buying Water), MARKET STALLS (buying a box) and HOUSES
(the host's whole house on the guest's screen, door and window shutters included, and the host's building changes
live).

Checked on 1.0.0.3549, with two copies of the game on one PC:
- Joining, seeing each other, moving, calling a mount, riding and dismounting.
- WEATHER: the guest shows the host's weather (the same cloud, wind and rain values on both screens). It only ever
  differs when the two games would have drifted apart, so on a normal day you will not notice anything.
- SMOOTHER MOVEMENT: the other player's character no longer freezes and jumps when the connection hiccups. Each game
  now waits as long as the other player's packets actually take (0.2 to 0.45 s) instead of a fixed 0.2 s. Measured
  on two copies on one PC, on the same movement: 277 freezes with the old fixed wait, 3 with the new one. The
  connection also resends a lost packet as soon as it is known lost (not yet measured between two real PCs).
- MARKET STALLS: the guest can buy the goods laid out on stalls and tables in town, and pick up and carry objects.
  HOLD E on the item ("Buy"): the item goes to the guest's inventory and the price comes out of the guest's own money
  (checked in Hernand: Rosemary, 8 copper).
- SHOPKEEPERS (NEW): the guest can use the merchants' shops. Press R ("Shop") on the merchant: the shop menu opens
  (Buy / Sell / Leave), "Buy" opens the merchant's goods and buying works (the item goes to the guest's inventory and
  the price comes out of the guest's own money), "Sell" opens the guest's inventory for selling, Esc goes back to the
  menu and "Leave" ends it. Checked with Delkin, the grocer in Hernand, several times (buying Water, 3 copper), and on
  12 November with the Vellua Farm Owner in Vellua Village: the menu, the shop's goods, and a real SALE (an item sold
  for 10 copper: it left the guest's inventory and the money went up). After a sale the menu also shows "Repurchase"
  (the game's own option; not tried).
  The merchant must be serving (not busy at his shelves) and the HOST must be nearby: merchants exist only around the
  host. FIXED on 12 November (checked: reproduced three times, no crash): the guest's game crashed (7 November) when
  it pressed "Shop" on a merchant whose shop was closed at that moment. The Vellua Farm Owner, for one, only sells
  from his table at some hours, and the host gets no "Shop" from him then. The guest's "Shop" there now does nothing,
  as for the host; come back when he is serving. Since 12 November the guest's loading after a fast travel into the
  host's area no longer waits 15 seconds for nothing (1.5 at most): a trip now loads in about 9-10 seconds instead of
  about 23, so towns and their merchants appear that much sooner for the guest (checked: Vellua and Hernand).
  Merchants appear when the HOST gets near them (as in the normal game: the Vellua ship manager stands about 150 m
  from the nexus, so he appears only once the host walks over); the guest gets each one about half a second after
  the host's game does. With two copies on ONE PC the copy in the background runs slowly and its merchants can
  appear several seconds later; on two PCs that does not happen.
- HOUSES (checked on 3576, two copies on one PC, 12 November): at the HOST's house the guest sees the host's whole
  house: walls, floors, roof, balcony, the door and the window shutters, also before the host gets there. When the
  host changes walls or floors in the construction mode, the guest sees the change right away. Checked: the host
  arriving while the guest waits at the house, the host opening and closing the construction mode six times and
  removing walls with the guest next to it, the host travelling far away and back: no crash. The guest can open the
  window shutters (E). Pets show for the guest. Furniture the host places shows for the guest too (checked: an
  archery target placed by the host next to the porch appeared at the same spot on the guest's screen). Since 12
  November the ground around the house looks the same for both (level grass): the guest used to see a pond beside
  the porch, the plot as it was before the house was built (HOST's cdmp.ini, [session2]: housing_share_level_states=1).
  Known gap: a door the host opens may still look closed for the guest. The guest should not try to build in the
  host's house.
- SHIPS (checked on 1.0.0.3663, 14 November, two copies on one PC): when the HOST sails its ship, the guest sees it
  where the host has it, moving and turning with it (drawn about 0.3 seconds behind: about 1.5 m at cruising speed,
  5 to 8 m at full sail), and the guest can board it and ride along. Checked: the guest climbed the ladder at
  the mooring, stood and walked on the deck while the host sailed at up to 14 m/s, and stayed on board.
  NEW in v23:
  * The ship's wheel. On the guest's screen it used to float about 3 m above the deck; it now sits in its mount, with
    the host's hands on it.
  * Both players on board. Each player now sees the other standing on the ship. Before, the host saw a guest who
    stood still on the deck left behind in the water (100 m behind at full sail), and the guest saw the host beside
    the wheel instead of at it. Measured after the change: within about 0.5 m of the right spot for both.
  * Walking on the deck. Before, a player walking on the deck looked frozen to the other player (the game does not
    send those positions); now each mod tells the other where its player stands on the ship.
  * A crash of the guest's game while joining with the host's ship out (it happened once in seven joins) now has a
    guard. The guard is in place but has not had to act yet; if the guest's game still closes while joining, join
    again.
  BOTH PCs need this same kit: v23 changes how the two mods talk to each other, so a PC with v22 and a PC with v23
  will not play together.
  Not covered yet: the sails look the same for both only by chance (their state is not sent). The guest's own ship as
  the host sees it: not tested.
  To turn all of it off: [session2] vehicle_follow=0 in the GUEST's cdmp.ini (and in the HOST's for the "both on
  board" part).
  If the guest's game crashes near the house, set the HOST's cdmp.ini, [session2]: housing_share_drop_gimmicks=waiting
  (the guest then loses the door, the shutters and the furniture: the doorway looks like a wall), or
  housing_share_rekey=0 (no walls at all). If it crashes when the host changes the house, set the GUEST's cdmp.ini,
  [session2]: housing_redraw=0 (the changes then show when the guest joins again). Keep the GUEST's
  housing_gimmick_guard=1: without it the guest crashed when the host opened the construction mode.

Checked on 1.0.0.3549 between two real PCs over Steam (one short session):
- Connecting, the guest playing their own save, moving, and the guest fast travelling.

Checked on the previous version, 1.0.0.3527, with two copies on one PC:
- Same time of day for both.
- Fighting: the guest damages and kills enemies, and enemies can kill the guest. Dying and reviving, both players.
  To try it quickly: the Abyss Nexus next to Valvegard Garrison puts you both in the middle of a fight.
- Climbing: each player sees the other climb.
- The guest plays THEIR save and takes it back on exit.
- The players and their mercenaries do not hurt each other.

KNOWN PROBLEMS
- STEAM ACHIEVEMENTS: in one session the guest's Steam account got ALL the host's achievements the moment it joined. The
  guest's game no longer unlocks any Steam achievement once it has joined a host, until it is restarted (so nothing the
  guest earns in co-op is unlocked on Steam either). The game cannot take back achievements already unlocked.
- In the host's world the guest sees the HOST's discovered Abyss Nexus points and can travel to them. Do not apply the
  guest's progress from a session (section 6) until it is known whether those points end up in the guest's own save.
- SWITCHING CHARACTER: seen working in a real session (each player sees the other's new character). Riding a horse as
  the new character is not synced.
  In one session where both players switched to Damiane, the guest's game crashed about a minute later, right after
  starting a fast travel. A guard now stops that exact crash, but it has not been seen working in a real session either.
- When the guest left, the HOST's town NPCs used to disappear. Fixed and seen working once in a real session (the guest
  left through the menu). Not yet seen after a guest CRASH: if the NPCs go, restart the host's game to get them back.
- Rope on the other player's copy does not work.
- SHOPKEEPERS: if the guest gets stuck in a shop (camera on the merchant, no menu, cannot walk; the menus still
  open), go back to the title and join again. To turn the
  shop windows off: GUEST's cdmp.ini, [session2]: guest_shop_branch=0. If the guest's game misbehaves in a town
  (crash, camera taken over by a scene, stuck in a dialog), turn the merchants' scenes off as before: GUEST's
  guest_seq_route=0, HOST's observer_seq_copy=0.
- HOUSES: if the guest's game misbehaves near a house, turn it off in the HOST's cdmp.ini, [session2]:
  housing_share=0 (the guest then sees its own houses, as before).
- SHIPS: if the guest's game misbehaves near the host's ship, set the GUEST's cdmp.ini, [session2]: vehicle_follow=0
  (the guest then sees its own copy of the ship, as before: it stays behind or drifts away).
- SHIPS: on the guest, two of the ship's mast lanterns can stay floating in the air where the ship was moored after
  the host sails away (seen at dusk). They belong to the guest's own copy of the ship, which stays there. Cosmetic.
- SHIPS: boarding is only checked at the mooring. If the guest falls through the deck or cannot climb the ladder of a
  ship that is already under way, wait for the host to stop.
- One HOST crash while a guest was joining (2026-11-06, two copies on one PC): inside the game's own drawing of static
  objects, not in a part of the mod we know of. Seen once in about 13 joins that day.
- MARKET STALLS: if buying or carrying misbehaves for the guest, turn it off in the GUEST's cdmp.ini, [session2]:
  interact_gate=0 (E on the host's objects then does nothing again, as before).
- The panel's marker and HP now follow the character you switched to; not seen live yet.
- Quests can mix: what the guest kills or does can also count for the host.
- Not tested yet: the loot from an enemy killed by the guest.


1. REQUIREMENTS (BOTH PLAYERS)
------------------------------
- Crimson Desert 1.0.0.3663 (right-click bin64\CrimsonDesert.exe > Properties > Details: File version).
  With another version the mod turns itself off, and if Steam updates the game you will need a new zip.
- Each player has their own Steam account and copy of the game. You must be Steam friends, and BOTH USE THE SAME ZIP.
- The guest needs a save of their own: they join with the most recent one and its character. Joining with no save at
  all has not been tested.
- Two players only: one host and one guest.
- BACK UP YOUR SAVES first: copy this whole folder somewhere else.
    %LOCALAPPDATA%\Pearl Abyss\CD\save
- While you play with the mod, what you save goes to a separate folder (cdmp_save_sandbox): your real save does not
  change until you apply your progress by hand (section 6).


2. INSTALLING (BOTH PLAYERS)
----------------------------
THE EASY WAY: THE LAUNCHER (new on 14 November). Unzip the whole zip into a folder of its own (not the game's) and
start cdmp_launcher.exe from that folder. It finds the game through Steam. Type your name, choose how to play and
press the big button: it copies the mod into the game folder, writes your settings and starts the game through Steam.
    Join a friend   You are the GUEST. "Automatic" connects to the only Steam friend who is playing; with "Add a
                    friend..." you pick the host by name, or paste their SteamID64.
    Host a game     You are the HOST. You can also say which friend may join.
    Single-player   Takes the mod out of the game folder and starts the game as Steam installed it. The mod comes
                    back when you choose Join or Host again.
If the kit is for another version of the game, the launcher says so instead of starting a game with the mod off.
Checked so far: finding the game, and installing, writing the settings and removing on a COPY of the game folder.
Not checked yet: starting the real game from it, and getting an update over the internet. If it does anything odd,
install by hand as below and tell us. Windows may warn that cdmp_launcher.exe comes from an unknown publisher (it
is not signed): More info > Run anyway. The cdmp.ini you had before is kept as cdmp.ini.before-launcher.

BY HAND, WITHOUT THE LAUNCHER: in Steam, right-click the game > Manage > Browse local files > bin64 folder.
Copy these there:
    winmm.dll   (loads the mod)
    cdmp.asi    (the mod)
    cdmp.ini    (the settings: it is already the GUEST's)

THE HOST: also copy cdmp.ini.host to bin64 and rename it to cdmp.ini, replacing the one above.
THE GUEST: the cdmp.ini in the zip is already yours; do not copy cdmp.ini.host.

Both: open cdmp.ini in Notepad and put your name in player_name=

Nothing else from the zip goes in bin64.


3. PLAYING
----------
No IP address and no ports to open: the connection goes through Steam. Start the game from Steam as usual.

1. The HOST starts the game and loads their save until they are in the world.
2. Then the GUEST starts the game and presses Play. It takes a little longer than normal.
3. Each player appears where they were in their own save, so you may be far apart. To meet, both fast travel to the
   same Abyss Nexus (M, double-click the point, Space to confirm).

THE PANEL at the top left of the screen shows who you are and the state of the session. F8 hides or shows it.
    HOST   Waiting for a player to join       Nobody is connected yet.
    HOST   'Name' is in your world            All good.
    GUEST  Looking for the host               See below if this does not change.
    GUEST  Connected to 'Name': wait...       The host is not ready. If you press Play now you may end up alone.
    GUEST  Connected to 'Name': press Play    Go ahead.
    GUEST  In 'Name's world                   All good.
    GUEST  Playing alone...                   You are not in the host's world: close the game and open it again.

HOW THE GUEST FINDS THE HOST: the mod connects to the ONLY Steam friend who is playing Crimson Desert right now.
This fails if the guest has another friend playing, or if the host's Steam privacy hides their game (Game details set
to Private). Then the guest must put the host's SteamID64 (17 digits) in cdmp.ini, under [steam]:
    peer_steamid=7656119xxxxxxxxxx
The guest's cdmp.log lists each friend who is playing, with their SteamID64. The host's SteamID64 is on their Steam
account page. Do not set Steam to Invisible or Offline while playing.
With the launcher there is no file to edit: "Join a friend" > "Add a friend..." and pick the host. The launcher
also shows your own SteamID64 with a Copy button, to send to the other player.


4. MOUNTS
---------
1. Inventory > Special Mount > click the mount. That summons it (another click or Space dismisses it).
2. Close the menu, all the way back to the game. H calls it.
3. Walk up until E Ride appears. R dismounts.


5. IF YOU DIE
-------------
On the death screen you must HOLD the key for a few seconds: U revives at the checkpoint; Q or E revives on the spot
and uses up an item.


6. SAVING YOUR PROGRESS
-----------------------
LEAVE IN THIS ORDER: first the GUEST, through the menu, and once the guest's game has closed, the HOST.
The guest takes their progress on exit. If the host leaves first, or the guest's game crashes or is force-closed, the
guest loses that session's progress.

THE GUEST, with the game closed (it makes a backup first and checks the save). Run it from the zip folder:
    powershell -ExecutionPolicy Bypass -File apply-guest-progress.ps1

THE HOST. This is the least tested part: do it only if your progress from that session matters to you.
1. Start the game up to the title screen and close it. Starting it exports the previous session to
   bin64\cdmp_save_exports.
2. Close Steam too. Note the name of the newest folder in cdmp_save_exports.
3. Check, without writing anything (N is your slot):
    powershell -ExecutionPolicy Bypass -File host_save_restore.ps1 -Generation <folder> -Slot N
4. If there are no errors, repeat with -Confirm at the end. First copy your whole save to a backup folder.


7. LEAVING AND COMING BACK
--------------------------
To exit the game or return to the title: in those dialogs you must HOLD Space for a few seconds.
If the guest exits normally, they just start the game again and press Play: the host does nothing.
If the guest's game crashes: wait until the guest's panel says "press Play" before pressing it. This case was fixed
recently and has not been fully tested: if the guest ends up alone, the host must restart their game.
If the host leaves, the guest is alone in a stopped world and loses that session's progress: the guest should leave too.


8. IF SOMETHING GOES WRONG
--------------------------
Keep these files from bin64 on both PCs and send them to whoever gave you the mod:
    every cdmp_*.log from that session, and cdmp.log
    cdmp_crash*.dmp  (if there are any)
For a network capture, set record=1 in the [sniffer] section of cdmp.ini before playing (about 25 MB a minute).

If the guest cannot get in: on joining they upload their save to the host and have 30 seconds. On a slow connection that
can fail. Set guest_own_save=0 in cdmp.ini on both PCs: the guest then plays a copy of the host's character and their
progress is not saved.

To uninstall: delete winmm.dll, cdmp.asi and cdmp.ini from bin64 (the launcher's "Single-player" removes the first
two for you).
