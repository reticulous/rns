/**
 * rnsd — RNS protocol task.
 *
 * Owns: identity, destinations, path table, transport state machine,
 *       links, resources. Zero networking/radio dependencies — receives
 *       RNS-format packets via ITS streams from transport tasks and
 *       sends them back the same way.
 *
 * See docs/component-plan.md §4 / §5.1 / §9 / §11.
 */
#pragma once

/** Bring up the rnsd task. Called from app_main between diptychInit()
 *  and diptychPostAppInit(). */
void rnsdInit(void);
