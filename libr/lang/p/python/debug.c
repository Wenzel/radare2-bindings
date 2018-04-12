/* r_debug */
static RDebugPlugin *py_debug_plugin = NULL;
// callbacks
static void *py_debug_info_cb = NULL;
static void *py_debug_attach_cb = NULL;
static void *py_debug_detach_cb = NULL;
static void *py_debug_select_cb = NULL;
static void *py_debug_threads_cb = NULL;
static void *py_debug_step_cb = NULL;
static void *py_debug_cont_cb = NULL;
static void *py_debug_wait_cb = NULL;
static void *py_debug_kill_cb = NULL;
static void *py_debug_frames_cb = NULL;
static void *py_debug_reg_read_cb = NULL;
static void *py_debug_reg_profile_cb = NULL;
static void *py_debug_map_get_cb = NULL;
static void *py_debug_modules_get_cb = NULL;
static void *py_debug_breakpoint_cb = NULL;

static RDebugInfo* py_debug_info(RDebug *dbg, const char *arg) {
	printf("py %s\n", __func__);
}

static int py_debug_attach(RDebug *dbg, int pid) {
	printf("py %s\n", __func__);
}

static int py_debug_detach(RDebug *dbg, int pid) {
	printf("py %s\n", __func__);
}

static int py_debug_select(int pid, int tid) {
	printf("py %s\n", __func__);
}

static RList* py_debug_threads(RDebug* dbg, int pid) {
	printf("py %s\n", __func__);
}

static int py_debug_step(RDebug* dbg) {
	printf("py %s\n", __func__);
}

static int py_debug_cont(RDebug *dbg, int pid, int tid, int sig) {
	printf("py %s\n", __func__);
}

static RDebugReasonType py_debug_wait(RDebug *dbg, int pid) {
	printf("py %s\n", __func__);
}

static bool py_debug_kill(RDebug *dbg, int pid, int tid, int sig) {
	printf("py %s\n", __func__);
}

static RList* py_debug_frames(RDebug *dbg, ut64 at) {
	printf("py %s\n", __func__);
}

static int py_debug_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	printf("py %s\n", __func__);
}

static char* py_debug_reg_profile(RDebug *dbg) {
	printf("py %s\n", __func__);
}

static RList* py_debug_map_get(RDebug *dbg) {
	printf("py %s\n", __func__);
}

static RList* py_debug_modules_get(RDebug *dbg) {
	printf("py %s\n", __func__);
}

static int py_debug_breakpoint(void *bp, RBreakpointItem *b, bool set) {
	printf("py %s\n", __func__);
}

static void Radare_plugin_debug_free(RDebugPlugin *ap) {
	free ((char *)ap->name);
	free ((char *)ap->license);
	free (ap);
}

static PyObject *Radare_plugin_debug(Radare* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RDebugPlugin *ap = R_NEW0 (RDebugPlugin);
	if (!ap) {
		return Py_False;
	}
	py_debug_plugin= ap;

	ap->name = getS (o,"name");
	ap->license = getS (o, "license");
	ap->bits = getI(o, "bits");
	ap->arch = getS (o, "arch");
	ap->canstep = getI(o, "canstep");

	ptr = getF (o, "info");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_info_cb = (void*)ptr;
		ap->info = py_debug_info;
	}
	ptr = getF (o, "attach");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_attach_cb = (void*)ptr;
		ap->attach = py_debug_attach;
	}
	ptr = getF (o, "detach");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_detach_cb = (void*)ptr;
		ap->detach = py_debug_detach;
	}
	ptr = getF (o, "select");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_select_cb = (void*)ptr;
		ap->select = py_debug_select;
	}
	ptr = getF (o, "threads");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_threads_cb = (void*)ptr;
		ap->threads = py_debug_threads;
	}
	ptr = getF (o, "step");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_step_cb = (void*)ptr;
		ap->step = py_debug_step;
	}
	ptr = getF (o, "cont");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_cont_cb = (void*)ptr;
		ap->cont = py_debug_cont;
	}
	ptr = getF (o, "wait");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_wait_cb = (void*)ptr;
		ap->wait = py_debug_wait;
	}
	ptr = getF (o, "kill");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_kill_cb = (void*)ptr;
		ap->kill = py_debug_kill;
	}
	ptr = getF (o, "frames");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_frames_cb = (void*)ptr;
		ap->frames = py_debug_frames;
	}
	ptr = getF (o, "reg_read");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_reg_read_cb = (void*)ptr;
		ap->reg_read = py_debug_reg_read;
	}
	ptr = getF (o, "reg_profile");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_reg_profile_cb = (void*)ptr;
		ap->reg_profile = py_debug_reg_profile;
	}
	ptr = getF (o, "map_get");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_map_get_cb = (void*)ptr;
		ap->map_get = py_debug_map_get;
	}
	ptr = getF (o, "modules_get");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_modules_get_cb = (void*)ptr;
		ap->modules_get = py_debug_modules_get;
	}
	ptr = getF (o, "breakpoint");
	if (ptr) {
		Py_INCREF (ptr);
		py_debug_breakpoint_cb = (void*)ptr;
		ap->breakpoint = py_debug_breakpoint;
	}


	Py_DECREF (o);

	RLibStruct lp = {};
	lp.type = R_LIB_TYPE_IO;
	lp.data = ap;
	lp.free = (void (*)(void *data))Radare_plugin_debug_free;
	r_lib_open_ptr (core->lib, "python.py", NULL, &lp);
	Py_RETURN_TRUE;
}
