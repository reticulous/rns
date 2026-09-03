import { ref } from 'vue'
import { useMenuStore } from 'spangap-browser/stores/menu'
import { registerWindowMount } from 'spangap-browser/lib/windowMounts'
import { registerTopbarIcon } from 'spangap-browser/lib/topbarIcons'
import MapWindow from '../panels/MapWindow.vue'
import NodesWindow from '../panels/NodesWindow.vue'
import GwSignal from '../panels/GwSignal.vue'
import IfacePills from '../panels/IfacePills.vue'

/* Visibility ref for the Status → Map floating window. Toggled by the menu
 * action below; <StraddleWindows/> binds the MapWindow component to it via the
 * mount registered below. Mirrors how spangap-browser/modules/advanced
 * exposes cliVisible/logVisible. */
export const mapVisible = ref(false)
export const nodesVisible = ref(false)

export function registerRnsd() {
  const menu = useMenuStore()

  /* One pill per switched-on interface class, ahead of the signal bars: the
   * medium's letter and how many peers are on it. The straddles publish them;
   * this component only renders what is there. */
  registerTopbarIcon({ id: 'rns-iface-pills', component: IfacePills })

  /* Gateway/infrastructure signal bars in the app header, left of the power
   * button — the received quality of the transport node that last relayed to us. */
  registerTopbarIcon({ id: 'rnsd-gw-signal', component: GwSignal })

  registerWindowMount({ id: 'nodes', title: 'Reticulum Nodes',
                        component: NodesWindow, visible: nodesVisible })
  registerWindowMount({ id: 'map', title: 'Reticulum Map',
                        component: MapWindow, visible: mapVisible })

  /* #if 0 — Show Nodes / Show Map removed from the menu; the NodesWindow /
   * MapWindow components and these visibility refs are kept for re-enabling. */
  if (false) {
    menu.register('status/nodes', 'Show Nodes',
      { type: 'action', action: () => { nodesVisible.value = !nodesVisible.value } })
    menu.register('status/map', 'Show Map',
      { type: 'action', action: () => { mapVisible.value = !mapVisible.value } })
  }
  /* #endif */
}
