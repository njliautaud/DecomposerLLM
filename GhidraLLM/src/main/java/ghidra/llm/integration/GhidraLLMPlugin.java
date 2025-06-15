package ghidra.llm.integration;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import resources.Icons;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidraLLM",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "LLM Integration for Ghidra",
    description = "Integrates LLM capabilities into Ghidra for enhanced binary analysis"
)
public class GhidraLLMPlugin extends ProgramPlugin {
    private LLMPanel llmPanel;
    private DockingAction showLLMPanelAction;

    public GhidraLLMPlugin(PluginTool tool) {
        super(tool, true, true);
        createActions();
    }

    @Override
    protected void init() {
        super.init();
        llmPanel = new LLMPanel(this);
        tool.addComponentProvider(llmPanel, true);
    }

    private void createActions() {
        showLLMPanelAction = new DockingAction("Show LLM Panel", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                llmPanel.setVisible(true);
            }
        };
        showLLMPanelAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, "LLM"));
        showLLMPanelAction.setEnabled(true);
        tool.addAction(showLLMPanelAction);
    }

    @Override
    public void programActivated(Program program) {
        llmPanel.programActivated(program);
    }

    @Override
    public void programDeactivated(Program program) {
        llmPanel.programDeactivated(program);
    }

    @Override
    public void programClosed(Program program) {
        llmPanel.programClosed(program);
    }
} 