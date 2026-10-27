"""Tk interface and background capture lifecycle."""
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk,filedialog
from .updates import apply,fetch,default_store
from .trust import PUBLIC_KEY,CATALOG_URL,APP_VERSION
from .location import load as load_location, save as save_location
from . import theme
from .capture_files import capture_destination
from .capture_library import migrate_legacy
from .prerequisites import inspect_support, download_installer, launch_installer, setup_failure


def start(*,smoke_test=False):
    from .supervisor import supervise
    root=tk.Tk();root.title('HXARK Sniffer');root.geometry('600x350');root.minsize(540,340)
    if smoke_test:root.withdraw()
    family=theme.apply(root)
    folder=default_store().parent;captures=folder/'captures';captures.mkdir(parents=True,exist_ok=True)
    dumps=folder/'dumps';dumps.mkdir(parents=True,exist_ok=True)
    events=queue.Queue();stop=threading.Event();running=False;closing=False;setting_up=False
    wow=load_location(folder) or Path(r'C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe')
    status=tk.StringVar(value='Starting…')
    detail=tk.StringVar(value='Getting ready to capture your game.')
    result_text=tk.StringVar(value='')
    panel=ttk.Frame(root,padding=28);panel.pack(fill='both',expand=True)
    heading=ttk.Frame(panel);heading.pack(fill='x')
    root._brand_mark=root._hxark_icon.subsample(16,16)
    ttk.Label(heading,image=root._brand_mark).pack(side='left',padx=(0,11))
    ttk.Label(heading,text='HXARK',font=(family,18,'bold')).pack(side='left')
    ttk.Label(heading,text=' / Sniffer',style='Muted.TLabel',font=(family,12)).pack(side='left',padx=(3,0))
    card=ttk.Frame(panel,style='Card.TFrame',padding=20);card.pack(fill='both',expand=True,pady=(24,20))
    ttk.Label(card,text='LOCAL CAPTURE',style='CardMuted.TLabel',font=(family,9,'bold')).pack(anchor='w')
    state_label=ttk.Label(card,textvariable=status,style='Card.TLabel',font=(family,19,'bold'),wraplength=440)
    state_label.pack(anchor='w',pady=(10,7))
    detail_label=ttk.Label(card,textvariable=detail,style='CardMuted.TLabel',wraplength=440)
    detail_label.pack(anchor='w')
    result_label=ttk.Label(card,textvariable=result_text,style='Card.TLabel',wraplength=440,font=(family,10,'bold'))
    result_label.pack(anchor='w',pady=(12,0))
    def resize_card(event):
        for label in (state_label,detail_label,result_label):label.configure(wraplength=max(180,event.width-42))
    card.bind('<Configure>',resize_card)
    bar=ttk.Frame(panel);bar.pack(fill='x')
    ttk.Label(bar,text=APP_VERSION+' · Saved on this PC',style='Muted.TLabel',font=(family,9)).pack(side='left')
    def open_captures():
        try:os.startfile(str(capture_destination(captures, dumps=dumps)))
        except (OSError,ValueError):
            result_text.set('Could not open captures. Your files remain saved on this PC.')
    ttk.Button(bar,text='Open captures',style='Primary.TButton',command=open_captures).pack(side='right')
    recovery=ttk.Button(bar,text='Locate WoW')
    setup_button=ttk.Button(card,text='Install capture support',style='Primary.TButton')
    if smoke_test:
        root.update_idletasks()
        result={'ui_initialized':True,'controls':['Open captures'],
                'capture_started':False,'network_used':False,
                'automatic_capture':True,'theme':'hxark-dark','brand_icon_loaded':bool(root._brand_mark),
                'background':root.cget('background'),'first_run_setup':True}
        root.destroy();return result
    def launch():
        nonlocal running
        if running or closing:return
        if not wow.is_file():
            status.set('WoW not found');detail.set('Select Wow.exe once.');recovery.pack(side='left');return
        recovery.pack_forget();running=True;stop.clear()
        def work():
            try:
                try:
                    if migrate_legacy(captures,dumps)['failed']:
                        events.put({'state':'library_warning'})
                except (OSError,ValueError):
                    events.put({'state':'library_warning'})
                try:
                    if CATALOG_URL:apply(fetch(CATALOG_URL),default_store(),PUBLIC_KEY)
                except Exception:pass  # The signed installed profile remains usable offline.
                supervise(wow,captures,stop,events.put,dumps=dumps)
            except Exception as exc:
                messages={
                    'unsupported_build':'This WoW build needs a compatibility update.',
                    'update_in_progress':'Another sniffer is already running.',
                    'insufficient_capture_disk':'Not enough free space for a capture.',
                    'capture_adapter_unavailable':'No capture interface available. Check Wireshark/Npcap.',
                    'too_many_capture_adapters':'Too many network interfaces for this preview.',
                    'readonly_process_access_denied':'Windows denied read access to WoW.',
                }
                message=messages.get(str(exc),'Capture unavailable. Check Wireshark/Npcap and the local receipt.')
                events.put({'state':'error','message':message})
            finally:events.put({'state':'finished'})
        threading.Thread(target=work,daemon=True).start()
    def check_support():
        nonlocal setting_up
        if running or setting_up or closing:return
        setting_up=True;stop.clear();setup_button.pack_forget();recovery.pack_forget()
        status.set('Checking capture support…');detail.set('Preparing your sniffer.')
        def work():
            try:events.put({'state':'support_checked','support':inspect_support()['state']})
            except Exception:events.put({'state':'support_checked','support':'unavailable'})
        threading.Thread(target=work,daemon=True).start()
    def install_support():
        nonlocal setting_up
        if running or setting_up or closing:return
        setting_up=True;stop.clear();setup_button.pack_forget()
        result_text.set('')
        status.set('Downloading capture support…')
        detail.set('Official Wireshark installer. Review its setup and Windows prompts.')
        def work():
            try:
                path=download_installer(folder/'setup',stop,lambda n:events.put({'state':'setup_progress','percent':n}))
                if stop.is_set():raise ValueError('setup_cancelled')
                events.put({'state':'setup_installing'})
                launch_installer(path,stop)
                events.put({'state':'setup_finished'})
            except Exception as exc:
                code=setup_failure(exc)
                events.put({'state':'setup_error','cancelled':code=='setup_cancelled','code':code})
        threading.Thread(target=work,daemon=True).start()
    def locate():
        nonlocal wow
        value=filedialog.askopenfilename(filetypes=[('WoW','Wow.exe')])
        if value:
            try:wow=save_location(folder,Path(value))
            except (OSError,ValueError):
                status.set('Location not saved');detail.set('Select an existing Wow.exe in a local folder.');return
            check_support()
    recovery.configure(command=locate)
    def poll():
        nonlocal running,setting_up
        try:
            while True:
                event=events.get_nowait();state=event['state']
                if state=='support_checked':
                    setting_up=False
                    if closing:root.destroy();return
                    if event['support']=='ready':launch()
                    elif event['support']=='missing':
                        status.set('One-time setup');detail.set('Install Wireshark with Npcap. Then open WoW as usual.')
                        setup_button.configure(text='Install capture support',command=install_support);setup_button.pack(anchor='w',pady=(12,0))
                    else:
                        status.set('Capture support needs attention')
                        detail.set('Wireshark is installed, but capture is unavailable. Check Npcap or reconnect your network.')
                        setup_button.configure(text='Check again',command=check_support);setup_button.pack(anchor='w',pady=(12,0))
                elif state=='setup_progress':
                    detail.set('Official Wireshark download · '+str(event['percent'])+'%')
                elif state=='setup_installing':
                    status.set('Finish setup');detail.set('Accept the installer and Windows prompts. Keep Npcap selected.')
                elif state=='setup_finished':
                    setting_up=False
                    if closing:root.destroy();return
                    check_support()
                elif state=='setup_error':
                    setting_up=False
                    if closing:root.destroy();return
                    status.set('Setup cancelled' if event['cancelled'] else 'Setup could not finish')
                    detail.set('You can retry. No capture has started.')
                    if not event['cancelled']:result_text.set('Setup: '+event['code'])
                    setup_button.configure(text='Retry setup',command=install_support);setup_button.pack(anchor='w',pady=(12,0))
                elif state=='finished':
                    running=False
                    if closing:root.destroy();return
                elif state=='error':
                    state_label.configure(foreground=theme.DANGER)
                    status.set('Needs attention');detail.set(event['message'])
                elif state=='saved':
                    state_label.configure(foreground=theme.TEXT)
                    count=event['files'];result_text.set('Last session: '+str(count)+' PKT '+('file' if count==1 else 'files')+' saved.')
                    status.set('Capture saved');detail.set('Your files are ready in Open captures.')
                elif state=='incomplete':
                    state_label.configure(foreground=theme.DANGER)
                    result_text.set((str(event['files'])+' PKT file(s). Some data needs review.') if event['files'] else 'No PKT saved. Capture needs review.');status.set('Capture needs review')
                    detail.set('Captured data and diagnostics are kept on this PC.')
                elif state=='library_warning':
                    result_text.set('Some older captures need review. Originals remain saved.')
                else:
                    state_label.configure(foreground=theme.TEXT)
                    labels={'arming':'Preparing network capture…','waiting':'Ready · waiting for WoW',
                            'awaiting_traffic':'WoW detected · waiting for game packets',
                            'reconnecting':'Reconnecting network capture…',
                            'network_wait':'Waiting for network…',
                            'recording':'Recording WoW','saving':'Saving PKT…'}
                    status.set(labels.get(state,state))
                    details={'arming':'Finding your game connection.',
                             'waiting':'Open WoW and play. Your PKT saves when you close the game.',
                             'awaiting_traffic':'Waiting for your first game connection.',
                             'recording':'Close WoW when finished. Your PKT saves automatically.',
                             'saving':'Checking and saving your captured packets.',
                             'reconnecting':'Looking for an available network interface.',
                             'network_wait':'Capture resumes automatically when your network is ready. Open WoW after Ready appears.'}
                    detail.set(details.get(state,''))
        except queue.Empty:pass
        theme.fit_content(root,panel)
        root.after(150,poll)
    def close():
        nonlocal closing
        closing=True;stop.set()
        if running or setting_up:status.set('Finishing…');return
        root.destroy()
    root.protocol('WM_DELETE_WINDOW',close);poll();check_support();root.mainloop()
